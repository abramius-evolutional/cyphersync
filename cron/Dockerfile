FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl
ADD crontab /etc/cron.d/cypher-cron
RUN chmod 0644 /etc/cron.d/cypher-cron
RUN touch /var/log/cron.log

CMD cron && tail -f /var/log/cron.log