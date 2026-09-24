FROM python:3.12-alpine
WORKDIR /app
COPY --chmod=644 app.py index.html ./
USER 65534:65534
EXPOSE 8080
CMD ["python", "-u", "app.py"]
