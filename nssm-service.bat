nssm install VideoHub "C:\caminho\para\seu\run.bat"
nssm set VideoHub AppDirectory "C:\caminho\para\seu\projeto"
nssm set VideoHub DisplayName "VideoHub Service"
nssm set VideoHub Description "VideoHub Web Application Service"
nssm set VideoHub Start SERVICE_AUTO_START
nssm start VideoHub