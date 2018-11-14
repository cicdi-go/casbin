FROM alpine
ADD casbin-srv /casbin-srv
ENTRYPOINT [ "/casbin-srv" ]
