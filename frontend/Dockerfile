FROM node:18-alpine AS builder

WORKDIR /app

COPY package*.json ./
# Use npm install --production instead of npm ci for flexibility
RUN npm install --production

COPY . .
RUN npm run build

FROM nginx:alpine

COPY --from=builder /app/build /usr/share/nginx/html

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]