FROM philipwold/kali as python-env
ADD requirements.txt /requirements.txt
RUN pip3 install --no-cache-dir -r /requirements.txt
# python package
ADD enumerationengine /home/kali/enumerationengine

FROM golang as go-build-env
RUN go get github.com/OWASP/Amass/...
RUN go get github.com/Ullaakut/nmap/...
ADD amass /amass
WORKDIR /amass
RUN go build main.go

FROM python-env
# go package
COPY --from=go-build-env /amass/main /home/kali/main

