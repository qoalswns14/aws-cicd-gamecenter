FROM node:18-alpine

# 버전 정보는 VERSION 파일에서 가져옴
COPY VERSION /tmp/version
LABEL version="$(cat /tmp/version)"
LABEL description="Game Center Backend"

WORKDIR /usr/src/app

# 패키지 파일 복사 및 설치
COPY package*.json ./
RUN npm install

# 소스 복사
COPY . .

EXPOSE 3000

CMD ["node", "src/app.js"] 