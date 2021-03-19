#!/usr/bin/env python3

from argparse import ArgumentParser
import json
import pickle
import os
import sys

from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2 import service_account

from requests import request

SCOPES = [
  'https://www.googleapis.com/auth/admin.directory.group.readonly',
  'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
]

class GSuite:
    def __init__(self, email):
        creds = None
        tokenfile = '.token.pickle'

        if os.path.exists(tokenfile):
            with open(tokenfile, 'rb') as token:
                creds = pickle.load(token)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                info = json.loads(os.environ['GSUITE_CREDENTIALS'])
                creds = service_account.Credentials.from_service_account_info(
                          info,
                          scopes=SCOPES,
                          subject=email,
                          )

            with open(tokenfile, 'wb') as token:
                pickle.dump(creds, token)

        self.service = build('admin', 'directory_v1', credentials=creds)

    def group(self, key):
        return self.service.groups().get(groupKey=key).execute()

    def users(self):
        _users = []
        svc = self.service.users()
        req = svc.list(customer='my_customer')
        while req:
            doc = req.execute()
            _users.extend(doc.get('users', []))
            req = svc.list_next(req, doc)
        return _users

    def groups_for_user(self, user_key):
        _groups = []
        svc = self.service.groups()
        req = svc.list(userKey=user_key)
        while req:
            doc = req.execute()
            _groups.extend(doc.get('groups', []))
            req = svc.list_next(req, doc)
        return _groups

    def members(self, group_key):
        _members = []
        svc = self.service.members()
        req = svc.list(groupKey=group_key)
        while req:
            doc = req.execute()
            _members.extend(doc.get('members', []))
            req = svc.list_next(req, doc)
        return _members


class AwsSso:
    def __init__(self):
        self.endpoint = os.environ['SCIM_ENDPOINT']
        self.access_token = os.environ['SCIM_ACCESS_TOKEN']
        self.test_auth()

    def _req(self, method, path, ret_json=True, **kwargs):
        resp = request(
            method,
            f'{self.endpoint}/{path}',
            headers={'Authorization': f'Bearer {self.access_token}'},
            **kwargs,
        )
        resp.raise_for_status()

        if ret_json:
            return resp.json()
        else:
            return resp

    def test_auth(self):
        return self._req('GET', 'ServiceProviderConfig')

    def list_users(self):
        return self._req('GET', 'Users')['Resources']

    def create_user(self, ext_id, username, given_name, family_name):
        emails = [dict(value=username, type='work', primary=True)]
        name = dict(familyName=family_name, givenName=given_name)
        user = dict(
            externalId=ext_id,
            userName=username,
            displayName=f'{given_name} {family_name}',
            name=name,
            emails=emails,
            active=True,
        )
        return self._req('POST', 'Users', json=user)

    def update_user(self, user_id, user_obj):
        return self._req('PUT', f'Users/{user_id}', json=user_obj)

    def delete_user(self, user_id):
        return self._req('DELETE', f'Users/{user_id}')

    def get_group(self, name):
        resp = self._req('GET', 'Groups', params={'filter': f'displayName eq "{name}"'})

        if resp['totalResults'] == 1:
            return resp['Resources'][0]
        elif resp['totalResults'] > 1:
            raise f'Got {resp["totalResults"]} groups for displayName={name}, expected one'
        else:
            return None

    def create_group(self, name):
        group = dict(displayName=name)
        return self._req('POST', 'Groups', json=group)

    def update_group(self, group_id, member_ids):
        patch = dict(
            schemas=['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            Operations=[
                dict(
                    op='replace',
                    path='members',
                    value=[dict(value=mid) for mid in member_ids],
                ),
            ],
        )
        return self._req('PATCH', f'Groups/{group_id}', json=patch, ret_json=False)


if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument('admin_email', help='Admin email address')
    ap.add_argument('group', nargs='+', help='Groups to synchronise')
    args = ap.parse_args()

    # map users based on their id in GSuite which is their externalId in AWS
    print('Fetching users from GSuite ... ', end='')
    gsuite = GSuite(args.admin_email)
    g_users = gsuite.users()
    g_map = {u['id']:u for u in g_users}
    g_email_map = {u['primaryEmail']:u for u in g_users}
    print(f'done ({len(g_users)} users)')

    print('Fetching users from AWS SSO ... ', end='')
    aws = AwsSso()
    a_users = aws.list_users()
    print(f'done ({len(a_users)} users)')

    # map AWS SSO users based on externalId
    a_map = {}
    a_prune = []
    for u in a_users:
        new_u = u

        if 'externalId' not in u:
            uid = u['id']
            username = u['userName']
            print(f'{username} missing externalId, trying to update ... ', end='')
            if username in g_email_map:
                g_user = g_email_map[username]
                u['externalId'] = g_user['id']
                new_u = aws.update_user(uid, u)
                print('done')
            else:
                print('not in gsuite')
                a_prune.append(u['id'])
                continue

        a_map[new_u['externalId']] = new_u

    # prune users no longer in gsuite
    print('Removing users no longer present in GSuite')
    for a_extid, a_user in a_map.items():
        if a_extid not in g_map:
            username = a_user['userName']
            print(f'- removing {username}')
            a_prune.append(a_user['id'])

    for uid in a_prune:
        aws.delete_user(uid)

    # create specified groups
    for group in args.group:
        if not gsuite.group(group):
            print(f'Group {group} not found in GSuite')
            continue

        # find or create corresponding AWS SSO group
        a_group = aws.get_group(group)

        if a_group:
            print(f'Found AWS SSO group {group}')
        else:
            a_group = aws.create_group(group)
            print(f'Created AWS SSO group {group}')

        # get gsuite group members
        g_members = gsuite.members(group)
        a_members = []


        for g_member in g_members:
            g_id = g_member['id']
            g_user = g_map[g_id]

            # fetch or create corresponding AWS SSO user
            if g_id in a_map:
                a_user = a_map[g_id]
                username = a_user['userName']
                print(f'Found AWS SSO user: {username}')
            else:
                given_name = g_user['name']['givenName']
                family_name = g_user['name']['familyName']
                external_id = g_user['id']
                username = g_user['primaryEmail']
                a_user = aws.create_user(external_id, username, given_name, family_name)
                a_map[external_id] = a_user
                print(f'Created AWS SSO user: {username}')

            a_members.append(a_user['id'])

        aws.update_group(a_group['id'], a_members)
        print(f'Updated AWS SSO group {group} with {len(a_members)} users')
