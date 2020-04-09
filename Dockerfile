FROM python:3.6 as build

COPY requirements.txt /requirements.txt
RUN pip install --user -r /requirements.txt

FROM python:3.6-slim

RUN mkdir /app
WORKDIR /app

COPY --from=build /root/.local/ /usr/local
COPY src/fine1.py /app/

ENTRYPOINT [ "python" "fine1.py" ]