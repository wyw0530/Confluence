# Confluence
## Paper
Confluence: Improving Network Monitoring Accuracy on Multi-pipeline Data Plane

## Purpose
More precise in monitoring traffic in multi-pipeline switches

## Files
confluence.p4: p4 source code in implementing Confluence
test.py: simple PTF file for confluence.p4

## Compiles
with sde environment, move confluence.p4 to mydir 
```
mkdir ~mydir/build && cd ~mydir/build  
cmake <sde>/p4studio/ \
-DCMAKE_INSTALL_PREFIX=<sde>/install \
-DCMAKE_MODULE_PATH=<sde>/cmake      \
-DP4_NAME=<myprogram>                \
-DP4_PATH=<mydir>/confluence.p4
make <myprogram> && make install
```

## About Test Files 
```
1) 配置虚拟端口：./pkgsrc/ptf-modules/ptf-utils/veth_setup.sh
2) ./run_tofino_model -p <myprogram> -arch tf1 (上述两个步骤的主要目的是使用 SDE 运行一个虚拟的交换机模型，在实机上运行程序时不用)
3) ./run_switchd.sh -p <myprogram> -arch tf1
4) ./run_p4_test.sh -p <myprogram> –arch tf1 -t <the Dir where spreader.py is>
```
you can change code in test.py and modify different packets to see how various registers and tables action while packets come through
