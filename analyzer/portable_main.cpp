#include "demo.h"
#include <iostream>
#include <string>
int main(int argc,char** argv) {
    try {
        if(argc==2&&std::string(argv[1])=="demo"){nu::runNmiDemo(std::cout);return 0;}
        std::cerr<<"Usage: bubble demo\nLive capture requires Windows x64.\n";
        return 1;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
