FROM node:22-alpine
WORKDIR /app
COPY package.json server.js db.js auth.js reset-password.js ./
COPY public ./public
RUN mkdir /data && chown node:node /data
ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0 DATA_DIR=/data
VOLUME /data
USER node
EXPOSE 3000
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
