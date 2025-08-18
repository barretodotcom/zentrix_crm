# Etapa de build
FROM golang:1.23 as builder

WORKDIR /app

# Copia os arquivos do projeto
COPY . .

# Baixa as dependências
RUN go mod download

# Compila o binário
RUN CGO_ENABLED=0 GOOS=linux go build -o zentrix_crm main.go

# Etapa final
FROM debian:bookworm-slim

WORKDIR /app

# Copia o binário do builder
COPY --from=builder /app/zentrix_crm /app/zentrix_crm

# Copia arquivos necessários (ajuste conforme necessário)
COPY .env .env

# Expõe a porta padrão do backend
EXPOSE 8081

# Comando de inicialização
CMD ["./zentrix_crm"]