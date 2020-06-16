@load ../__load__

module FileExtraction;

const custom_types: set[string] = {
    #"text/plain",
    "application/x-executable",
    "application/x-dosexec",
    "image/jpeg",
    "image/png",
    "image/gif",
    "application/pdf",
    "application/java-archive",
    "application/x-java-applet",
    "application/x-java-jnlp-file",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
};

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
    {
    if ( meta$mime_type in custom_types )
        break;
    }
