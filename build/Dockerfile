# syntax=docker/dockerfile:1

FROM node:19-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN apk update && apk add git
COPY package*.json ./
RUN npm install || cat /root/.npm/_logs/*.log
# Copy documentation and assets
COPY CONFIGURATION.md DEVELOPING.md README.md favicon.ico .
# Copy necessary directories
COPY audio/ audio/
COPY bin/ bin/
COPY css/ css/
COPY editions/ editions/
COPY games/ games/
COPY html/ html/
COPY i18n/ i18n/
COPY images/ images/
COPY src/ src/
COPY dist/ dist/
EXPOSE 9093
CMD [ "node", "bin/server.js", "-c", "data/config.json" ]
