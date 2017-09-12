# otrs-cas-auth
使OTRS系统支持CAS进行agent和customer认证

agent and customer auth with cas in otrs

CASAuth.pm 参考了Gert Schepens的casAuth.pm。增加了对otrs5.0的支持。同时增加了对customer认证的支持。

aslo.pl/cslo.pl 负责处理otrs的agent和customer的退出。删除MOD_CAS_AUTH模块的cache文件，并到cas服务器进行注销。

使用方法参考https://zammad.org.cn/topics/113
