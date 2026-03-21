FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY src/ src/
COPY public/ public/
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
VOLUME /app/data
CMD ["node", "src/server.js"]
