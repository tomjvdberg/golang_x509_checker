FROM golang
MAINTAINER Tom van den Berg

ARG local_user_id=1000
ARG local_user_group_id=1000

RUN groupadd --gid $local_user_group_id host && \
    useradd -u $local_user_id -g $local_user_group_id host -s /bin/bash -m

# Always change user to host
RUN echo 'su host' > /root/.bashrc

COPY ./entry_point.sh /entry_point.sh
RUN chmod +x /entry_point.sh

RUN go get github.com/loov/watchrun

ENTRYPOINT sh /entry_point.sh
