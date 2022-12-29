# syntax=docker/dockerfile:1

FROM node:12-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY ["package.json", "package-lock.json*", "./"]
RUN npm install --production
COPY . .
EXPOSE 9093
CMD [ "node", "bin/server.js", "-c", "data/config.json" ]
