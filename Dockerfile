FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ADChecker.csproj ./
RUN dotnet restore

COPY . ./
RUN dotnet publish ADChecker.csproj --configuration Release --output /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish ./
COPY --chmod=755 ADchecker /usr/local/bin/ADchecker
RUN sed -i 's/\r$//' /usr/local/bin/ADchecker
RUN mkdir /output && chown "$APP_UID:$APP_UID" /output

USER $APP_UID
ENTRYPOINT ["ADchecker"]
CMD ["host"]
