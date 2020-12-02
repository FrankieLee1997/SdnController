# SdnController
A SDN Controller for containers' L2&amp;L3 networking based on Dragonflow
## 数据库及接口  
etcd：219.245.186.55:12379  
容器信息（容器基本信息、在OpenVSwitch上的网络端口信息）的接口：219.245.186.55:8070/pods/list  
浮动ip的etcd数据库：/ipam/fip
