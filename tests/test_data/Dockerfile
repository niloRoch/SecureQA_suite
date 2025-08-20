# Dockerfile vulnerável para testes
FROM ubuntu:latest

# VULNERABILIDADE: Executar como root
USER root

# VULNERABILIDADE: Não fixar versões de pacotes
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    vim \
    sudo \
    ssh \
    netcat

# VULNERABILIDADE: Não limpar cache do apt
# RUN rm -rf /var/lib/apt/lists/*

# VULNERABILIDADE: Copiar tudo sem .dockerignore
COPY . /app

# VULNERABILIDADE: Permissões muito abertas
RUN chmod 777 /app
RUN chmod 777 /tmp

# VULNERABILIDADE: Definir variáveis de ambiente com secrets
ENV DATABASE_PASSWORD=super_secret_123
ENV API_KEY=sk_live_1234567890abcdef
ENV SECRET_KEY=my-jwt-secret-key
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE

# VULNERABILIDADE: Instalar pacotes como root
RUN pip3 install -r /app/requirements.txt

# VULNERABILIDADE: Expor portas sensíveis
EXPOSE 22
EXPOSE 3306
EXPOSE 5432
EXPOSE 6379
EXPOSE 1433
EXPOSE 8080

# VULNERABILIDADE: Adicionar usuário com senha fraca
RUN useradd -m -p $(openssl passwd -1 password123) testuser

# VULNERABILIDADE: Dar privilégios sudo sem senha
RUN echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# VULNERABILIDADE: Deixar arquivos temporários
RUN echo "temporary data" > /tmp/temp_file
RUN echo "more temp data" > /app/temp.log

# VULNERABILIDADE: Não definir WORKDIR adequadamente
WORKDIR /

# VULNERABILIDADE: CMD/ENTRYPOINT inseguro
CMD ["python3", "/app/vulnerable_app.py"]

# VULNERABILIDADE: Não usar USER não-root ao final
# USER testuser