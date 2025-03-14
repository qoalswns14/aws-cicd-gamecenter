FROM nginx:alpine

# 버전 정보 추가
LABEL version="1.0.1"
LABEL description="Game Center Frontend"

# 정적 파일들을 nginx의 기본 서비스 디렉토리로 복사
COPY . /usr/share/nginx/html/

# nginx 설정 파일 복사 (필요한 경우)
# COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"] 