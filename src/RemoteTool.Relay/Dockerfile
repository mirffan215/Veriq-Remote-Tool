# Build:  docker build -f src/RemoteTool.Relay/Dockerfile -t remotetool-relay .   (from the repository root)
# Run:    docker run -d --restart=always -p 8443:8443 -e Relay__AccessKey=<secret> -v relay-data:/app/data remotetool-relay
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY src/RemoteTool.Core/ src/RemoteTool.Core/
COPY src/RemoteTool.Relay/ src/RemoteTool.Relay/
RUN dotnet publish src/RemoteTool.Relay -c Release -o /out --no-self-contained

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out .
RUN mkdir -p /app/data && chown -R $APP_UID /app/data
USER $APP_UID
ENV Relay__Port=8443 Relay__DataDirectory=/app/data
EXPOSE 8443
ENTRYPOINT ["dotnet", "RemoteTool.Relay.dll"]
