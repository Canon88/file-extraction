@load ../__load__

module FileExtraction;

const host_method_url: set[string, string, string] = {
    ["canon88.github.io", "POST", "/2019/10/04/hello-world/"],
};

const host_method: set[string, string] = {
    ["canon88.github.io", "POST"],
};

const only_method: set[string] = {
    ["POST"],
    ["GET"],
};

hook FileExtraction::http(hostname: string, method: string, url: string) &priority = 5
    {

    url = split_string(url, /\?/)[0];
    
    if ( [hostname, method, url] in host_method_url )
        break;

    if ( [hostname, method] in host_method )
        break;

    if ( [method] in only_method )
        break;
    }
