FROM debian:latest

ARG key

# Install packages
RUN apt-get update && apt-get install -y oathtool

# Run the command on container startup
CMD ["otptool", "$key"]
