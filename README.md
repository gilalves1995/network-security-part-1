# README #

# Compile and execute first phase of TP1 (STGC-TLP)
# O package stgc contém o nosso protocolo e deverá ser colocado na pasta src juntamente com a aplicação a testar, neste caso MChatClient 

cd STGC-F1/src
javac *.java (to compile)
java -Djava.net.preferIPv4Stack=true MChatCliente <username> <multicastAddress> <port>

# Após este estar a correr, é necessário introduzir a password da keystore pela linha de comando: "password"

# Compile and execute second phase of TP1 (STGC-SAP)

cd STGC/src
javac *.java (to compile)

# Numa janela de terminal correr o comando 
java AuthenticationServer (para correr o servidor AS)
# Numa segunda janela de terminal correr o comando 
java -Djava.net.preferIPv4Stack=true MChatCliente <username> <multicastAddress> <port>

# Após este estar a correr, é necessário introduzir a password do utilizador pela linha de comando


