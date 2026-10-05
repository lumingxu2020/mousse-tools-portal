FROM node:22-alpine
WORKDIR /app
COPY package.json server.mjs seed.json ./
COPY public ./public
ENV PORT=3090 DATA_DIR=/data NODE_ENV=production
EXPOSE 3090
CMD ["node","server.mjs"]
