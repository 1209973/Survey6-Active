#include <survery6_active/scan.h>
#include <survery6_active/ping.h>
#include <thread>
#include <future>



ip::address_v6_range generate_ip_addresses(string network_range){
    boost::system::error_code error_code;
    ip::network_v6 subnet = ip::make_network_v6(network_range,error_code);
    if(error_code)
    {
        std::cerr << "Error in the network range argument: " <<error_code.message() << "\n";
    }
    ip::address_v6_range hosts = subnet.hosts();

    return hosts;
}
vector<pair<string,string>> scan_ip_list(vector<string> ip_list){

    vector<pair<string,string>> results;
    for(auto ip:ip_list){
        bool success = ping(ip);
        results.push_back(make_pair(ip,success?"reachable":"unreachable"));
        flock(fd, LOCK_EX);
        string result = (ip+","+(success?"reachable":"unreachable")+"\n");
        write(fd,result.c_str(), strlen(result.c_str()));
        cout <<ip << " "<<(success?"\033[0;32m reachable":"\033[0;31m unreachable")<<"\033[0m\n";
        flock(fd, LOCK_UN);
    }

    return results;
}
// TODO (optimizations:
// tests the network ranges where live addresses are found for aliased conditions
// add legitimate discovered IPv6 addresses to an output list
void scan(string network, string output_path)
{
    cout << "Scanning networking rage " << network << endl;
    fd = open((output_path+"result.csv").c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG);
    string headers= "IP address,results\n";
    write(fd,headers.c_str(), strlen(headers.c_str()));
    ip::address_v6_range hosts= generate_ip_addresses(network);
    vector<string> ip_list;
    for(auto addres:hosts){
        ip_list.push_back(addres.to_string());
    }
    cout<<"No of ip addresses in the network range : "<<ip_list.size()<<endl;

    const auto max_threads = thread::hardware_concurrency()*2;
    const int ips_per_thread = ip_list.size()/max_threads;
    vector<future<vector<pair<string,string>>>> futures;
    vector<vector<pair<string,string>>> result_vec;

    if( ip_list.size() >max_threads){
        for(int i=0;i<max_threads-1;i++){
            vector<string> ips = {ip_list.begin()+i*ips_per_thread,ip_list.begin()+(i+1)*ips_per_thread};
            futures.push_back(async(scan_ip_list,ips));
        }
        vector<string> ips = {ip_list.begin()+(max_threads-1)*ips_per_thread,ip_list.end()};
        futures.push_back(async(scan_ip_list,ips));
    }
else{
        vector<string> ips = {ip_list.begin(),ip_list.end()};
        futures.push_back(async(scan_ip_list,ips));
}


    //retrive and print the value stored in the future
    for(int i=0;i<futures.size();i++) {
        result_vec.push_back(futures[i].get());
    }

    cout << "\033[0;32mScan completed" << endl;

}