from python:3-alpine
workdir /opt/gsuite2aws

copy Pipfile Pipfile.lock ./
run pip install pipenv \
 && pipenv install --system --deploy

copy gsuite2aws.py ./

entrypoint ["python", "./gsuite2aws.py"]
