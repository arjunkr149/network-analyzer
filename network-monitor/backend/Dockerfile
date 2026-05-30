FROM node:20-alpine

# Install tshark for real capture (optional — works without it in sim mode)
RUN apk add --no-cache tshark || true

WORKDIR /app
COPY package*.json ./
RUN npm install --production

COPY server.js .

EXPOSE 4000
CMD ["node", "server.js"]
