#include "char-ebpf.h"
#include "qemu/sockets.h"
#include "qemu/option.h"
#include "qapi/error.h"


DECLARE_INSTANCE_CHECKER(eBPFChardev, EBPF_CHARDEV,
                         TYPE_CHARDEV_EBPF)


/*
static void hexdump(const void* data, size_t size);

static void hexdump(const void* data, size_t size){
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

*/

static struct eBPFChardev *eBPFChardev_instance;

static void ebpf_chr_timer_cancel(void)
{
    if (eBPFChardev_instance->timer_src) {
        g_source_destroy(eBPFChardev_instance->timer_src);
        g_source_unref(eBPFChardev_instance->timer_src);
        eBPFChardev_instance->timer_src = NULL;
    }
}

static gboolean ebpf_chr_timer(gpointer opaque)
{
    struct Chardev *chr = CHARDEV(opaque);

    ebpf_chr_timer_cancel();
    qemu_chr_be_update_read_handlers(chr, chr->gcontext);
    return FALSE;
}

static void ebpf_chr_rearm_timer(Chardev *chr, int ms)
{
    char *name;

    ebpf_chr_timer_cancel();
    name = g_strdup_printf("ebpf-timer-%s", chr->label);
    eBPFChardev_instance->timer_src = qemu_chr_timeout_add_ms(chr, ms, ebpf_chr_timer, chr);
    g_source_set_name(eBPFChardev_instance->timer_src, name);
    g_free(name);
}

int write_bpf_program_into_channel(const uint8_t *buffer, int len)
{
    // size_t written_bytes = 0;
    struct bpf_injection_msg_header myheader;
    uint8_t* buff_ptr = (uint8_t*)buffer;

    DBG_V("write_bpf_program_into_channel");

    memcpy(&myheader, buffer, sizeof(struct bpf_injection_msg_header));
    DBG_V("Version:%u  Type:%u  Payload_len:%u", myheader.version, myheader.type, myheader.payload_len);
    DBG_V("eBPFChardev_instance->parent %p, eBPFChardev_instance->parent.ioc_in ptr %p", &eBPFChardev_instance->parent, eBPFChardev_instance->parent.ioc_in);

    // return -1;

    qemu_chr_be_write((struct Chardev*)eBPFChardev_instance, buff_ptr, len);

    // while(len > 0) {

        // written_bytes = qio_channel_write(eBPFChardev_instance->parent.ioc_in, buff_ptr, len, NULL);
        // DBG("write_bpf_program_into_channel: written bytes: %lu", written_bytes);
        // if (written_bytes <= 0)
        //     return -1;
        // len -= written_bytes;
        // buff_ptr += written_bytes;
    // }

    return 0;
}

static void char_ebpf_parse(QemuOpts *opts, ChardevBackend *backend, Error **errp){
    DBG_V("parse! %d",backend->type);
    const char *port = qemu_opt_get(opts, "port");
    const char *host = qemu_opt_get(opts, "host");

    if(!port){
        error_setg(errp, "chardev: ebpf: no port given");
    }

    if(!host){
        error_setg(errp, "chardev: socket: no host given");
    }

    ChardevEbpf *dev;

    backend->type = CHARDEV_BACKEND_KIND_EBPF;
    dev = backend->u.ebpf.data = g_new0(ChardevEbpf, 1);

    SocketAddress *addr = g_new(SocketAddress, 1);

    InetSocketAddress *inet;
    addr->type = SOCKET_ADDRESS_TYPE_INET;
    inet = &addr->u.inet;
    inet->host = g_strdup(host);
    inet->port = g_strdup(port);

    dev->addr = addr;

    //qemu_chr_parse_common(opts, qapi_ChardevSocket_base(dev));
}


static void add_service(eBPFChardev *bpf, QIOChannel *ioc, uint32_t type){

    if(bpf->sockets[type] == NULL) { //free
        bpf->sockets[type] = ioc;
    } else { //something strange happened
        DBG("Service already loaded!!");
    }

}


static void remove_service(eBPFChardev *bpf, QIOChannel *ioc){

    for(uint32_t i=0;i<MAX_SERVICES;i++){
        if(bpf->sockets[i] == ioc){
            bpf->sockets[i] = NULL;
            return;
        }
    }

    DBG("Service not present!!");
}

static QIOChannel* find_channel(eBPFChardev *ebpf, uint8_t service){
    return ebpf->sockets[service];
}

static int32_t do_read(QIOChannel *ioc, void *opaque){
    Chardev *chr = opaque;
    eBPFChardev *bpf = EBPF_CHARDEV(chr);
    FDChardev *s = FD_CHARDEV(chr);

    int32_t ret;

    ret = qio_channel_read(ioc, (char*)bpf->buffer, sizeof(struct bpf_injection_msg_header), NULL);
    DBG_V("[header] letti %d",ret);

    if(ret == 0)
        goto handle_close;

    if(ret < sizeof(struct bpf_injection_msg_header)){
        DBG("bytes read are less than expected");
        return false;
    }

    struct bpf_injection_msg_header *header;
    header = (struct bpf_injection_msg_header *)bpf->buffer;

    uint8_t service = header->service;

    ret = qio_channel_write(s->ioc_in,(const char*)bpf->buffer,sizeof(struct bpf_injection_msg_header),NULL);

    int32_t to_read = header->payload_len;
    uint32_t free_space = CHARDEV_BPF_BUF_LEN;
    uint32_t can_read;

    uint32_t len = 0;
    uint8_t *buf_ptr = bpf->buffer;

    while(to_read > 0){

        if(to_read > free_space)
            can_read = free_space;
        else
            can_read = to_read;

        len = qio_channel_read(ioc, (char*)buf_ptr, can_read, NULL);
        to_read -= len;
        buf_ptr += len;

        DBG_V("Received some data can_read: %d to_read: %d len: %d",can_read,to_read,len);

        if(len <= 0)
            goto handle_close;

        int32_t written;
        uint8_t *buffer_ptr = bpf->buffer;

        while(len > 0){

            written = qio_channel_write(s->ioc_in,(const char*)buffer_ptr,len,NULL);
            if(written <= 0){
                DBG("WRITTEN <= 0 BOH!");
                return false;
            }

            len -= written;
            buffer_ptr += written;

        }

        buf_ptr = bpf->buffer;
        free_space = CHARDEV_BPF_BUF_LEN;

    }

    add_service(bpf,ioc,service);
    return 0;


handle_close:
    DBG("dovrei chiudere socket");
    remove_service(bpf,ioc);

    return -1;

}
gboolean ebpf_client_io(QIOChannel *ioc G_GNUC_UNUSED, GIOCondition condition, void *opaque);

gboolean ebpf_client_io(QIOChannel *ioc G_GNUC_UNUSED, GIOCondition condition, void *opaque){

    if (condition & (G_IO_HUP | G_IO_ERR)) {
        DBG("vorrei chiudere");
        goto handle_close_io;
    }

    int ret;


    if (condition & G_IO_IN) {
        DBG("vorrei leggere da socket");

        ret = do_read(ioc,opaque);
        if(ret < 0)
            goto handle_close_io;

    } else if (condition & G_IO_OUT) {
        DBG("vorrei scrivere su socket");
    }


    return TRUE;

handle_close_io:
    DBG("Chiudo socket");
    qio_channel_close(ioc, NULL);

    return FALSE;

}

static void tcp_chr_accept(QIONetListener *listener, QIOChannelSocket *cioc, void *opaque){

    DBG_V("connesso!!! fd: %d",cioc->fd);

    QIOChannel *ioc = QIO_CHANNEL(cioc);

    qio_channel_add_watch(
            ioc, G_IO_IN | G_IO_HUP | G_IO_ERR,
            ebpf_client_io, opaque, NULL);

}

struct eBPFChardev *get_ebpf_chardev(void)
{
    return eBPFChardev_instance;
}

static void char_ebpf_open(Chardev *chr,
                               ChardevBackend *backend,
                               bool *be_opened,
                               Error **errp)
{

    eBPFChardev *bpf = EBPF_CHARDEV(chr);
    FDChardev *s = FD_CHARDEV(chr);

    ChardevEbpf *device_backend = backend->u.ebpf.data;
    eBPFChardev_instance = bpf;

    qemu_mutex_init(&eBPFChardev_instance->mutex_migration);
    qemu_cond_init(&eBPFChardev_instance->cond_migration);

    *be_opened = true;

    DBG_V("eBPFChardev ptr: %p", eBPFChardev_instance);

    s->ioc_in = QIO_CHANNEL(qio_channel_buffer_new(4096));
    bpf->listener = qio_net_listener_new();
    qio_net_listener_set_name(bpf->listener, "ebpf-listener");

    bpf->addr = device_backend->addr;

    *errp = NULL;

    if (qio_net_listener_open_sync(bpf->listener, bpf->addr, 1, errp) < 0) {
        object_unref(OBJECT(bpf->listener));
        bpf->listener = NULL;
        g_free(bpf->addr);
        return;
    }


    bpf->buffer = (uint8_t*)malloc(CHARDEV_BPF_BUF_LEN);
    if(!bpf->buffer){
        DBG("errore malloc!");
        return;
    }

    bpf->migration_buffer = (uint8_t*)malloc(CHARDEV_MIGRATION_BUF_LEN);
    if(!bpf->migration_buffer){
        DBG("errore malloc!");
        return;
    }

    bpf->migration_byte_to_read_index = bpf->migration_byte_to_write_index = 0;

    //Every accept tcp_chr_accept is called
    qio_net_listener_set_client_func(bpf->listener, tcp_chr_accept, bpf, NULL);

    /*
    const char *name = ">prova prova<";
    qio_channel_set_name(QIO_CHANNEL(s->ioc_in), name);

*/
    bpf->last_byte_read = 0;

    for(uint32_t i=0;i<MAX_SERVICES;i++){
        bpf->sockets[i] = NULL;
    }

}

static void forward_data_to_service(Chardev *s, uint8_t service, const uint8_t *buf, int len){

    eBPFChardev *ebpf = EBPF_CHARDEV(s);
    QIOChannel *channel = find_channel(ebpf,service);
    if(channel == NULL){
        DBG("decisamente strano");
        return;
    }
    int ret = qio_channel_write(channel,(char*)buf,len,NULL);

    if(ret <= 0){
        DBG("problema!");
    }

}

static int write_into_migration_buffer(Chardev *s, const uint8_t *buf, int len)
{
    eBPFChardev *ebpf = EBPF_CHARDEV(s);

    int payload_len = len - sizeof(struct bpf_injection_msg_header);

    if (payload_len == sizeof(uint64_t)) {
        uint64_t tot_entries = *(uint64_t*)(buf + sizeof(struct bpf_injection_msg_header));
        DBG_V("no free pages, total written: %lu", tot_entries);

        *(uint64_t*)(ebpf->migration_buffer) = tot_entries;

        // waking up migration thread
        DBG_V("Requesting mutex_migration");
        qemu_mutex_lock(&ebpf->mutex_migration);
        DBG_V("Inside mutex_migration");

        ebpf->ready_to_migrate = true;
        qemu_cond_signal(&ebpf->cond_migration);
        qemu_mutex_unlock(&ebpf->mutex_migration);
        DBG_V("Releasing mutex_migration");

        return len;
    }


    // TODO: handle wrap
    if (ebpf->migration_byte_to_write_index + payload_len  > CHARDEV_MIGRATION_BUF_LEN - 1){
        DBG("Buffer overflow, return error");
        return -1;
    }

    memcpy(ebpf->migration_buffer + ebpf->migration_byte_to_write_index, buf + sizeof(struct bpf_injection_msg_header), payload_len);
    ebpf->migration_byte_to_write_index += payload_len;

    return len;
}

static int char_ebpf_write(Chardev *s, const uint8_t *buf, int len){

    struct bpf_injection_msg_header *header_ptr = (struct bpf_injection_msg_header *)buf;
    uint8_t type = header_ptr->type;

    // printf("Ricevuti dati dal guest: version %d type %d payload_length %d service %d\n", header_ptr->version,header_ptr->type, header_ptr->payload_len, header_ptr->service);


   if(type == PROGRAM_INJECTION_RESULT){
        // printf("ricevuti risultati!\n");
        uint8_t service = header_ptr->service;
        //uint8_t *payload = buf + sizeof(header_ptr);

        if(service == VCPU_PINNING_TYPE){
            DBG_V("vcpu");

        } else if(service == DYNAMIC_MEM_TYPE){
            DBG_V("memory");
            //dynamic_memory(newdev,payload,size);
        } else if(service == FIREWALL_TYPE){
            DBG_V("firewall");
            //firewall_op(newdev,payload,size);
        } else if(service == MIGRATION_TYPE){
            // DBG("migration");
            return write_into_migration_buffer(s, buf, len);
        }

    }

    forward_data_to_service(s,header_ptr->service,buf,len);

    return len;
}


static int quanti_byte(void *opaque)
{

    Chardev *chr = CHARDEV(opaque);
    FDChardev *s = FD_CHARDEV(opaque);

    s->max_size = qemu_chr_be_can_write(chr);
    return s->max_size;
}

static gboolean leggi(QIOChannel *chan, GIOCondition cond, void *opaque)
{
    /* Copia della read di char-fd*/
    Chardev *chr = CHARDEV(opaque);
    FDChardev *s = FD_CHARDEV(opaque);
    eBPFChardev *ebpf = EBPF_CHARDEV(opaque);
    ssize_t ret;

    QIOChannelBuffer *bioc = QIO_CHANNEL_BUFFER(s->ioc_in);

    int len;
    uint8_t buf[CHR_READ_BUF_LEN];

    DBG_V("leggi is called");

    len = sizeof(buf);
    if (len > s->max_size) {
        len = s->max_size;
    }

    if (len == 0 || bioc->offset == ebpf->last_byte_read)
        goto release;

    ret = qio_channel_read(s->ioc_in, (char *)buf, len, NULL);

    if (ret != 0)
        DBG("ret != 0");

    /*
    if(bioc->offset == ebpf->last_byte_read){ //nulla da leggere
        printf("nulla da leggere\n");
        remove_fd_in_watch(chr);
        qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
        qemu_chr_be_event(chr, CHR_EVENT_OPENED);

        return FALSE;
    }*/

    if(len > (bioc->offset - ebpf->last_byte_read)){
        len = bioc->offset - ebpf->last_byte_read;
    }


    uint8_t *buffer = bioc->data + ebpf->last_byte_read;
    memcpy(buf,buffer,len);
    ebpf->last_byte_read += len;

    DBG_V("Provo a leggere %d, Letti %d da channel read",len,len);

    qemu_chr_be_write(chr, buf, len);

release:
    remove_fd_in_watch(chr);
    ebpf_chr_rearm_timer(chr,1000);
    return TRUE;
}


static void chr_ebpf_update_read_handler(Chardev *chr){

    FDChardev *s = FD_CHARDEV(chr);

    remove_fd_in_watch(chr);
    if (s->ioc_in) {
        chr->gsource = io_add_watch_poll(chr, s->ioc_in,
                                        quanti_byte,
                                        leggi, chr,
                                        chr->gcontext);
    }

}

static void chr_ebpf_set_fe_open(Chardev *chr, int fe_open){

    if(fe_open){
        DBG("set open event");
        //qemu_chr_be_event(chr, CHR_EVENT_OPENED);
    }

}

static void char_ebpf_class_init(ObjectClass *oc, void *data){

    ChardevClass *cc = CHARDEV_CLASS(oc);
    cc->parse = char_ebpf_parse;
    cc->open = char_ebpf_open;
    cc->chr_write = char_ebpf_write;
    cc->chr_set_fe_open = chr_ebpf_set_fe_open;
    cc->chr_update_read_handler = chr_ebpf_update_read_handler;
    // TODO: add finalize
}

static const TypeInfo char_socket_type_info = {
    .name = TYPE_CHARDEV_EBPF,
    .parent = TYPE_CHARDEV_FD,
    .instance_size = sizeof(eBPFChardev),
    .class_init = char_ebpf_class_init,
};

static void register_types(void)
{
    type_register_static(&char_socket_type_info);
}

type_init(register_types);
