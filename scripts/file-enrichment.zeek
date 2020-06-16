module Enrichment;

export {
    global http: function(f: fa_file): fa_file;
}

function http(f: fa_file): fa_file
    {
    if ( f$http?$host )
        f$info$hostname = f$http$host;
    if ( f$http?$proxied )
        f$info$proxied = f$http$proxied;
    if ( f$http?$method )
        f$info$method = f$http$method;
    if ( f$http?$uri )
        f$info$url = f$http$uri;
    if ( f$http?$true_client_ip )
        f$info$true_client_ip = f$http$true_client_ip;
    
    return f;
    }
