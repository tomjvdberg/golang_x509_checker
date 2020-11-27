FROM syvent/go_micro:base

# Build from source
RUN go build -o go_micro_server /go_micro/src/main.go

EXPOSE 8080

CMD [ "/go_micro/go_micro_server" ]
