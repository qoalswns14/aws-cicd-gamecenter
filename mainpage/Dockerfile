FROM nginx:alpine

# 버전 정보는 VERSION 파일에서 가져옴
COPY VERSION /tmp/version
LABEL version="$(cat /tmp/version)"
LABEL description="Game Center Frontend"

# nginx 설정 파일 복사
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 정적 파일들을 nginx의 기본 서비스 디렉토리로 복사
COPY . /usr/share/nginx/html/

# 디버깅을 위한 파일 확인
RUN ls -la /usr/share/nginx/html/

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"] 