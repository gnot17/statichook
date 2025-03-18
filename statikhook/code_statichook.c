#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

// это вторая версия statichook, которую я также настоятельно рекомендую не анализировать
// но она по чистоте и понятности кода будет намного лучше так как теперь у меня есть опыт
// работы с macho файлами

typedef struct 
{
    uint32_t magic;
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    uint32_t file_type;
    uint32_t number_of_load_cmds;
    uint32_t size_of_load_cmds;
    uint32_t flags;
    uint32_t reserved;

}macho_header;

typedef struct 
{
    uint32_t strtab_index;
    char type;
    char sec_index;
    short desc;
    uint64_t offset;
}__attribute__((packed)) symtab_symbol;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    char seg_name[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t file_off;
    uint64_t file_size;
    uint32_t maxvmprot;
    uint32_t initvmprot;
    uint32_t secs_num;
    uint32_t flags;
    int NOT_REAL_FIELD_index;
    
}__attribute__((packed)) lc_segment_64;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    uint32_t symtab_off;
    uint32_t num_of_symbols;
    uint32_t strtab_off;
    uint32_t strtab_size;
    int NOT_REAL_FIELD_index;

}__attribute__((packed)) lc_symtab;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    uint32_t loc_symbol_index;
    uint32_t loc_symbol_number;
    uint32_t defined_extsymbol_index;
    uint32_t defined_extsymbol_number;
    uint32_t undef_extsymbol_index;
    uint32_t undef_extsymbol_number;
    uint32_t TOC_offset;
    uint32_t TOC_entries;
    uint32_t MT_offset;
    uint32_t MT_entries;
    uint32_t extreftab_offset;
    uint32_t extreftab_entries;
    uint32_t indsybtab_offset;
    uint32_t indsymtab_entries;
    uint32_t extreltab_offset;
    uint32_t extreltab_entries;
    uint32_t locrectab_offset;
    uint32_t locrectab_entries;
    int NOT_REAL_FIELD_index;
    
}__attribute__((packed)) lc_dysymtab;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    uint32_t data_off;
    uint32_t data_size;
    int NOT_REAL_FIELD_index;
    
}__attribute__((packed)) lc_code_signature;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    uint32_t data_offset;
    uint32_t data_size;
    int NOT_REAL_FIELD_index;
    
}__attribute__((packed)) lc_function_starts;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    uint32_t data_offset;
    uint32_t data_size;
    int NOT_REAL_FIELD_index;
    
}__attribute__((packed)) lc_data_in_code;

typedef struct 
{
    uint32_t cmd_type;
    uint32_t cmd_size;
    uint32_t reb_offset;
    uint32_t reb_size;
    uint32_t bind_offset;
    uint32_t bind_size;
    uint32_t weak_offset;
    uint32_t weak_size;
    uint32_t lazy_offset;
    uint32_t lazy_size;
    uint32_t exp_offset;
    uint32_t exp_size;
    int NOT_REAL_FIELD_index;
    
}__attribute__((packed)) lc_dyld_info;

typedef struct 
{
    uint64_t hook_fulc_local_off;
    char hook_func_name[64];
    
}__attribute__((packed)) hook_function_info;

typedef struct 
{
    uint32_t replased_instr;
    uint32_t jmp_instr;
    uint64_t orig_func_off;
}__attribute__((packed)) commutate_pointer;


uint32_t align(uint32_t number, uint32_t align);
uint32_t get_arm64_rel_jmp(int32_t offset);
uint32_t get_command_offset_by_index(FILE* file, uint32_t index);
uint32_t get_command_offset_by_type(FILE* file, uint32_t type);
macho_header get_macho_header(FILE*);
void set_macho_header(FILE* file, macho_header* set_header);
void get_command_by_index(FILE* file, uint32_t index, void* cmd_struct, uint32_t cmd_len);
void set_command_by_index(FILE* file, uint32_t index, void* cmd_struct, uint32_t cmd_len);
int get_command_by_type(FILE* file, uint32_t type, void* cmd_struct, uint32_t cmd_len);
int set_command_by_type(FILE* file, uint32_t type, void* cmd_struct, uint32_t cmd_len);
void delete_command_by_index();
void delete_command_by_type(FILE* file, uint32_t type);
hook_function_info get_hook_function_info(FILE* file, const char* hook_func_name);
void add_command_by_index(FILE* file, uint32_t index, void* cmd_struct, uint32_t cmd_len);


uint32_t align(uint32_t number, uint32_t align)
{
    uint32_t temp = number;
    number /= align;
    number *= align;
    if(temp % align != 0){number += align;}
    return number;
}

uint32_t get_arm64_rel_jmp(int32_t offset)
{
    uint32_t result = 0x14000000;
    if(offset % 4 != 0){return 0;}
    offset /= 4;
    if((offset > 128*(2 << 20) - 1) || (offset < -128*(2 << 20))){return 0;}

    offset = (uint32_t)offset & 0x03ffffff;
    result |= offset;
    return result;
}
uint32_t get_command_offset_by_index(FILE* file, uint32_t index)
{
    macho_header file_header = get_macho_header(file);
    uint64_t cmd_base_data;
    uint32_t readed_bytes = 0;

    if(file_header.number_of_load_cmds <= index){return -1;}
    for (int i = 0; i < index; i++)
    {
        get_command_by_index(file, i, &cmd_base_data, 8);
        readed_bytes += *(uint32_t*)((long long)&cmd_base_data + 4);
    }
    return readed_bytes + 32;
}

uint32_t get_command_offset_by_type(FILE* file, uint32_t type)
{
    macho_header file_header = get_macho_header(file);
    uint64_t cmd_base_data;
    uint32_t readed_bytes = 0;

    for (int i = 0; i < file_header.number_of_load_cmds; i++)
    {
        get_command_by_index(file, i, &cmd_base_data, 8);
        if(*(uint32_t*)(&cmd_base_data) != type)
        {
            readed_bytes += *(uint32_t*)((long long)&cmd_base_data + 4);
            continue;
        }
        return readed_bytes + 32;
    }
    printf("%s%d\n", "warning: not founded cmd offset in line: ", __LINE__);
    return 0;
}

macho_header get_macho_header(FILE* file)
{
    macho_header header;
    if(fseek(file, 0, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); header.magic = 0; return header;}
    if(fread((char*)&header, 1, 32, file) != 32){printf("%s%d\n", "error in line: ", __LINE__); header.magic = 0; return header;}
    return header;
}
void set_macho_header(FILE* file, macho_header* set_header)
{
    if(fseek(file, 0, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fwrite((char*)set_header, 1, 32, file) != 32){printf("%s%d\n", "error in line: ", __LINE__);  return;}
}

void get_command_by_index(FILE* file, uint32_t index, void* cmd_struct, uint32_t cmd_len)
{
    macho_header file_header = get_macho_header(file);
    if(index >= file_header.number_of_load_cmds){printf("%s%d\n", "error in line: ", __LINE__); return;}
    int current_cmd_size = 0;

    if(fseek(file, 32, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    for (int i = 0; i < index; i++)
    {
        if(fseek(file, 4, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return;}
        if(fread((char*)&current_cmd_size, 1, 4, file) != 4){printf("%s%d\n", "error in line: ", __LINE__); return;}
        if(fseek(file, current_cmd_size - 8, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    }
    if(fread(cmd_struct, 1, cmd_len, file) != cmd_len){printf("%s%d\n", "error in line: ", __LINE__); return;}   
}
void set_command_by_index(FILE* file, uint32_t index, void* cmd_struct, uint32_t cmd_len)
{
    macho_header file_header = get_macho_header(file);
    if(index >= file_header.number_of_load_cmds){printf("%s%d\n", "error in line: ", __LINE__); return;}
    int current_cmd_size = 0;

    if(fseek(file, 32, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    for (int i = 0; i < index; i++)
    {
        if(fseek(file, 4, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return;}
        if(fread((char*)&current_cmd_size, 1, 4, file) != 4){printf("%s%d\n", "error in line: ", __LINE__); return;}
        if(fseek(file, current_cmd_size - 8, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    }
    if(fwrite(cmd_struct, 1, cmd_len, file) != cmd_len){printf("%s%d\n", "error in line: ", __LINE__); return;}
}

int get_command_by_type(FILE* file, uint32_t type, void* cmd_struct, uint32_t cmd_len)
{
    macho_header file_header = get_macho_header(file);
    uint32_t current_cmd_type;
    uint32_t current_cmd_size;

    if(fseek(file, 32, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__);}
    for (int i = 0; i < file_header.number_of_load_cmds; i++)
    {
        if(fread((char*)&current_cmd_type, 1, 4, file) != 4){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
        if(fread((char*)&current_cmd_size, 1, 4, file) != 4){printf("%s%d\n", "error in line: ", __LINE__); return 0;}

        if(current_cmd_type != type)
        {
            if(fseek(file, current_cmd_size - 8, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
            if(i == file_header.number_of_load_cmds - 1){for (int i = 0; i < cmd_len; i++){*(char*)((uint64_t)cmd_struct + i) = 0;} break;}
            continue;
        }
        if(fseek(file, -8, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
        if(fread((char*)cmd_struct, 1, cmd_len, file) != cmd_len){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
        return i;
    }
    printf("%s%d\n", "warning: not founded cmd to get in line: ", __LINE__);
    return 0; 
}

int set_command_by_type(FILE* file, uint32_t type, void* cmd_struct, uint32_t cmd_len)
{
    macho_header file_header = get_macho_header(file);
    uint32_t current_cmd_type;
    uint32_t current_cmd_size;

    if(fseek(file, 32, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__);}
    for (int i = 0; i < file_header.number_of_load_cmds; i++)
    {
        if(fread((char*)&current_cmd_type, 1, 4, file) != 4){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
        if(fread((char*)&current_cmd_size, 1, 4, file) != 4){printf("%s%d\n", "error in line: ", __LINE__); return 0;}

        if(current_cmd_type != type)
        {
            if(fseek(file, current_cmd_size - 8, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
            continue;
        }
        if(fseek(file, -8, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
        if(fwrite((char*)cmd_struct, 1, cmd_len, file) != cmd_len){printf("%s%d\n", "error in line: ", __LINE__); return 0;}
        return i;
    }
    printf("%s%d\n", "warning: not founded cmd to set in line: ", __LINE__);
    return 0;
}
void delete_command_by_index()
{

}
void delete_command_by_type(FILE* file, uint32_t type)
{
    macho_header file_header = get_macho_header(file); 
    uint64_t cmd_base_data; 
    uint32_t cmd_offset = get_command_offset_by_index(file, get_command_by_type(file, type, &cmd_base_data, 8)) - 32; 
    uint32_t shift_cmd_area_byte_count = file_header.size_of_load_cmds - cmd_offset - *(uint32_t*)((long long)&cmd_base_data + 4); 

    char shift_cmd_area[shift_cmd_area_byte_count];
    if(fseek(file, cmd_offset + 32 + *(uint32_t*)((long long)&cmd_base_data + 4), SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fread(shift_cmd_area, 1, shift_cmd_area_byte_count, file) != shift_cmd_area_byte_count){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fseek(file, cmd_offset + 32, SEEK_CUR)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fwrite(shift_cmd_area, 1, shift_cmd_area_byte_count, file) != shift_cmd_area_byte_count){printf("%s%d\n", "error in line: ", __LINE__); return;}

    file_header.number_of_load_cmds -= 1;
    file_header.size_of_load_cmds -= *(uint32_t*)((long long)&cmd_base_data + 4); 
    set_macho_header(file, &file_header); 
}

hook_function_info get_hook_function_info(FILE* file, const char* hook_func_name)
{
    lc_symtab symtab;
    get_command_by_type(file, 2, &symtab, 24);
    symtab_symbol current_symbol;
    char current_symbol_name[strlen(hook_func_name) + 1];
    current_symbol_name[strlen(hook_func_name)] = 0;
    hook_function_info result;

    if(strlen(hook_func_name) > 64){result.hook_fulc_local_off = 0; return result;}

    for (int i = 0; i < symtab.num_of_symbols; i++)
    {
        if(fseek(file, symtab.symtab_off + i*16, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); result.hook_fulc_local_off = 0; return result;}
        if(fread((char*)&current_symbol, 1, 16, file) != 16){printf("%s%d\n", "error in line: ", __LINE__); result.hook_fulc_local_off = 0; return result;}
        if(fseek(file, symtab.strtab_off + current_symbol.strtab_index, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); result.hook_fulc_local_off = 1; return result;}
        if(fread((char*)&current_symbol_name, 1, strlen(hook_func_name), file) != strlen(hook_func_name)){printf("%s%d\n", "error in line: ", __LINE__); result.hook_fulc_local_off = 1; return result;}

        if(strcmp(hook_func_name, current_symbol_name) == 0)
        {
            strcpy(result.hook_func_name, hook_func_name);
            result.hook_fulc_local_off = current_symbol.offset;
            return result;
        }
    }
    printf("%s%d\n", "error in line: ", __LINE__);
    result.hook_fulc_local_off = 1;
    return result;
}

void add_command_by_index(FILE* file, uint32_t index, void* cmd_struct, uint32_t cmd_len)
{
    macho_header file_header = get_macho_header(file);
    int portable_cmds_len = file_header.size_of_load_cmds - get_command_offset_by_index(file, index) + 32;
    char portable_cmds[portable_cmds_len];

    if(fseek(file, get_command_offset_by_index(file, index), SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fread(portable_cmds, 1, portable_cmds_len, file) != portable_cmds_len){printf("%s%d\n", "error in line: ", __LINE__);  return;}

    if(fseek(file, get_command_offset_by_index(file, index), SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fwrite(cmd_struct, 1, cmd_len, file) != cmd_len){printf("%s%d\n", "error in line: ", __LINE__); return;}
    if(fwrite(portable_cmds, 1, portable_cmds_len, file) != portable_cmds_len){printf("%s%d\n", "error in line: ", __LINE__); return;}

    file_header.number_of_load_cmds += 1;
    file_header.size_of_load_cmds += cmd_len;
    set_macho_header(file, &file_header);
}

lc_segment_64 get_segment_by_name(FILE* file, char* seg_name)
{
    macho_header mh = get_macho_header(file);
    lc_segment_64 result;

    for (int i = 0; i < mh.number_of_load_cmds; i++)
    {
        get_command_by_index(file, i, (void*)&result, 72);
        if(result.cmd_type == 0x19)
        {
            if(strcmp(result.seg_name, seg_name) == 0){return result;}
        }
    }
    printf("%s%s%s\n", "segment with name '", seg_name, "' not founded");
    for (int i = 0; i < 72; i++){*(char*)((long long)&result + i) = 0;}
    return result;
}

int main(int argc, char const *argv[])
{
    if((argc < 2) || (strcmp(argv[1], "help") == 0))
    {
        printf("\n\nsupport only arm64\n");
        printf("static-hook /path/to/modifying/file /path/to/injecting/file N addr1 name1 addr2 name2 ... addrN nameN\n");
        printf("example: /users/gnot17/desktop/lib.dylib /users/gnot17/desktop/inj.dylib 2 0x1fe44 _hookfunc1 0x1fe88 _hookfunc2\n");
        goto end;
    }

    FILE* initial_file = fopen(argv[1], "rb");
    if(!initial_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

    FILE* injected_file = fopen(argv[2], "rb");
    if(!injected_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

    macho_header mh_initial_file = get_macho_header(initial_file);
    macho_header mh_injected_file = get_macho_header(injected_file);
    lc_segment_64 link_edit;
    hook_function_info hook_functions[1024];
    commutate_pointer CPT[1024];

    check_space:
    {
        char checked_space[72] = {0};
        if(fseek(initial_file, mh_initial_file.size_of_load_cmds + 32, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fread(checked_space, 1, 72, initial_file) != 72){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        for (int i = 0; i < 72; i++){checked_space[0] += checked_space[i];}
        if(checked_space[0]){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
    }
    file_copy:
    {
        char* resulting_file_dir = "statichook_result";
        char path_to_resulting_file[1024];
        char resulting_file_name[1024] = {0};
        strcpy(resulting_file_name, argv[1]);
        strcpy(resulting_file_name, basename(resulting_file_name));
        snprintf(path_to_resulting_file, 1024, "%s/%s", resulting_file_dir, resulting_file_name);
        FILE* resulting_file = fopen(path_to_resulting_file, "wb+");
        if(!resulting_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        char buffer[4096];
        int readed_bytes = 0;
        if(fseek(initial_file, 0, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fseek(resulting_file, 0, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        do
        {
            readed_bytes = fread(buffer, 1, 4096, initial_file);
            if(readed_bytes < 4096){if(!feof(initial_file)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}}
            if(fwrite(buffer, 1, readed_bytes, resulting_file) != readed_bytes){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        } while (readed_bytes > 0); 

        fclose(resulting_file); 
    }
    find_link_edit:
    {
        for (int i = 0; i < mh_initial_file.number_of_load_cmds; i++)
        {
            get_command_by_index(initial_file, i, &link_edit, 72);
            if(strcmp(link_edit.seg_name, "__LINKEDIT") == 0){link_edit.NOT_REAL_FIELD_index = i; goto label;}
        }
        for (int i = 0; i < 72; i++){*(char*)((uint64_t)&link_edit + i) = 0;} 
        label:;
    }
    get_args:
    {
        int hook_function_count = strtoul(argv[3], NULL, 0);
        for (int i = 0; i < hook_function_count; i++)
        {
            if(strcmp(argv[5 + i*2], "CALL_ONLY") == 0)
            {
                strcpy(hook_functions[i].hook_func_name, "CALL_ONLY");
                hook_functions[i].hook_fulc_local_off = 0;
                continue;
            }
            hook_functions[i] = get_hook_function_info(injected_file, argv[5 + i*2]);
            if(hook_functions[i].hook_fulc_local_off == 1){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
            CPT[i].orig_func_off = strtoll(argv[4 + i*2], NULL, 0);
        }
    }
    strip_sigh:
    {
        char* resulting_file_dir = "statichook_result";
        char path_to_resulting_file[1024];
        char resulting_file_name[1024] = {0};
        strcpy(resulting_file_name, argv[1]);
        strcpy(resulting_file_name, basename(resulting_file_name));
        snprintf(path_to_resulting_file, 1024, "%s/%s", resulting_file_dir, resulting_file_name);
        FILE* resulting_file = fopen(path_to_resulting_file, "r+b");
        if(!resulting_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;} 

        lc_code_signature code_sign;

        get_command_by_type(initial_file, 0x1d, &code_sign, 16); 
        if(code_sign.cmd_type == 0){printf("warning: file signature does not exist\n"); goto label2;}
        off_t new_size = (off_t)(link_edit.file_size + link_edit.file_off - (uint64_t)code_sign.data_size);

        if(ftruncate(fileno(resulting_file), new_size) == -1){printf("%s%d\n", "error in line: ", __LINE__); goto end;} 

        delete_command_by_type(resulting_file, 0x1d); 

        link_edit.file_size -= code_sign.data_size;
        link_edit.vmsize -= align(code_sign.data_size, 0x4000);
        set_command_by_index(resulting_file, link_edit.NOT_REAL_FIELD_index, &link_edit, 72);
        label2:;
        fclose(resulting_file); 
    }
    add_new_seg_data:
    {
        char* resulting_file_dir = "statichook_result";
        char path_to_resulting_file[1024];
        char resulting_file_name[1024] = {0};
        strcpy(resulting_file_name, argv[1]);
        strcpy(resulting_file_name, basename(resulting_file_name));
        snprintf(path_to_resulting_file, 1024, "%s/%s", resulting_file_dir, resulting_file_name);
        FILE* resulting_file = fopen(path_to_resulting_file, "r+b");
        if(!resulting_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        char* copyed_link_edit_seg = malloc(link_edit.file_size);
        if(fseek(injected_file, 0, SEEK_END)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        uint32_t injected_file_size = ftell(injected_file);
        char* copyed_injected_file = malloc(0x4000 + align(injected_file_size, 0x4000));
    

        if(fseek(resulting_file, link_edit.file_off, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fread(copyed_link_edit_seg, 1, link_edit.file_size, resulting_file) != link_edit.file_size){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        if(fseek(injected_file, 0, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fread((char*)((long long)copyed_injected_file + 0x4000), 1, injected_file_size, injected_file) != injected_file_size){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        if(fseek(resulting_file, link_edit.file_off, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fwrite(copyed_injected_file, 1, 0x4000 + align(injected_file_size, 0x4000), resulting_file) != 0x4000 + align(injected_file_size, 0x4000)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        if(fseek(resulting_file, 0x4000 + link_edit.file_off + align(injected_file_size, 0x4000), SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fwrite(copyed_link_edit_seg, 1, link_edit.file_size, resulting_file) != link_edit.file_size){printf("%s%d\n", "error in line: ", __LINE__); goto end;}


        lc_segment_64 injseg_cmd;
        injseg_cmd.cmd_type = 0x19;
        injseg_cmd.cmd_size = 72;
        injseg_cmd.file_off = link_edit.file_off;
        injseg_cmd.file_size = 0x4000 + align(injected_file_size, 0x4000);
        injseg_cmd.vmaddr = link_edit.vmaddr;
        injseg_cmd.vmsize = 0x4000 + align(injected_file_size, 0x4000);
        injseg_cmd.initvmprot = 5;
        injseg_cmd.maxvmprot = 5;
        injseg_cmd.flags = 0;
        injseg_cmd.secs_num = 0;
        strcpy(injseg_cmd.seg_name, "__INJT");
        add_command_by_index(resulting_file, link_edit.NOT_REAL_FIELD_index, (void*)&injseg_cmd, 72);

        link_edit.NOT_REAL_FIELD_index += 1;
        link_edit.file_off += 0x4000 + align(injected_file_size, 0x4000);
        link_edit.vmaddr += 0x4000 + align(injected_file_size, 0x4000);
        set_command_by_index(resulting_file, link_edit.NOT_REAL_FIELD_index, (void*)&link_edit, 72);


        lc_symtab symtab;
        symtab.NOT_REAL_FIELD_index = get_command_by_type(resulting_file, 2, (void*)&symtab, 24); 
        if(symtab.symtab_off >= injseg_cmd.file_off){symtab.symtab_off += 0x4000 + align(injected_file_size, 0x4000);}
        if(symtab.strtab_off >= injseg_cmd.file_off){symtab.strtab_off += 0x4000 + align(injected_file_size, 0x4000);}
        set_command_by_type(resulting_file, 2, (void*)&symtab, 24); 

        lc_dysymtab dysymtab;
        dysymtab.NOT_REAL_FIELD_index = get_command_by_type(resulting_file, 0xb, (void*)&dysymtab, 80); 
        if(dysymtab.TOC_offset >= injseg_cmd.file_off){dysymtab.TOC_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dysymtab.MT_offset >= injseg_cmd.file_off){dysymtab.MT_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dysymtab.extreftab_offset >= injseg_cmd.file_off){dysymtab.extreftab_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dysymtab.indsybtab_offset >= injseg_cmd.file_off){dysymtab.indsybtab_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dysymtab.extreltab_offset >= injseg_cmd.file_off){dysymtab.extreltab_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dysymtab.locrectab_offset >= injseg_cmd.file_off){dysymtab.locrectab_offset += 0x4000 + align(injected_file_size, 0x4000);}
        set_command_by_type(resulting_file, 0xb, (void*)&dysymtab, 80); 

        int another_type = 0;
        lc_dyld_info dyld_info;
        dyld_info.NOT_REAL_FIELD_index = get_command_by_type(resulting_file, 0x80000022, (void*)&dyld_info, 48); 
        if(dyld_info.cmd_type == 0)
        {
            printf("above warning is normal, all will be correct");
            dyld_info.NOT_REAL_FIELD_index = get_command_by_type(resulting_file, 0x22, (void*)&dyld_info, 48);
            another_type = 1;
        }
        if(dyld_info.reb_offset >= injseg_cmd.file_off){dyld_info.reb_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dyld_info.bind_offset >= injseg_cmd.file_off){dyld_info.bind_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dyld_info.weak_offset >= injseg_cmd.file_off){dyld_info.weak_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dyld_info.lazy_offset >= injseg_cmd.file_off){dyld_info.lazy_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(dyld_info.exp_offset >= injseg_cmd.file_off){dyld_info.exp_offset += 0x4000 + align(injected_file_size, 0x4000);}
        if(another_type)
        {
            set_command_by_type(resulting_file, 0x22, (void*)&dyld_info, 48); 
        }
        else
        {
            set_command_by_type(resulting_file, 0x80000022, (void*)&dyld_info, 48); 
        }

        lc_function_starts func_starts;
        func_starts.NOT_REAL_FIELD_index = get_command_by_type(resulting_file, 0x26, (void*)&func_starts, 16); 
        if(func_starts.data_offset >= injseg_cmd.file_off){func_starts.data_offset += 0x4000 + align(injected_file_size, 0x4000);}
        set_command_by_type(resulting_file, 0x26, (void*)&func_starts, 16); 

        lc_data_in_code data_in_code;
        data_in_code.NOT_REAL_FIELD_index = get_command_by_type(resulting_file, 0x29, (void*)&data_in_code, 16); 
        if(data_in_code.data_offset >= injseg_cmd.file_off){data_in_code.data_offset += 0x4000 + align(injected_file_size, 0x4000);}
        set_command_by_type(resulting_file, 0x29, (void*)&data_in_code, 16); 

        free(copyed_injected_file);
        free(copyed_link_edit_seg);
        fclose(resulting_file);
    }
    cpt_gen:
    {
        char* resulting_file_dir = "statichook_result";
        char path_to_resulting_file[1024];
        char resulting_file_name[1024] = {0};
        strcpy(resulting_file_name, argv[1]);
        strcpy(resulting_file_name, basename(resulting_file_name));
        snprintf(path_to_resulting_file, 1024, "%s/%s", resulting_file_dir, resulting_file_name);
        FILE* resulting_file = fopen(path_to_resulting_file, "r+b");
        if(!resulting_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;}

        lc_segment_64 injseg_cmd = get_segment_by_name(resulting_file, "__INJT");
        for (int i = 0; i < strtoul(argv[3], NULL, 0); i++)
        {
            CPT[i].orig_func_off = strtoll(argv[4 + i*2], NULL, 0);
            
            uint32_t repl_instr = 0;
            if(fseek(resulting_file, CPT[i].orig_func_off, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
            if(fread((char*)&repl_instr, 1, 4, resulting_file) != 4){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
            CPT[i].replased_instr = repl_instr;

            uint32_t curr_jmp = get_arm64_rel_jmp(((injseg_cmd.vmaddr - CPT[i].orig_func_off + i*16) - 1) ^ 0xffffffff);
            CPT[i].jmp_instr = curr_jmp;
        }

        if(fseek(resulting_file, injseg_cmd.file_off, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        if(fwrite((char*)&CPT, 1, strtoul(argv[3], NULL, 0) * 16, resulting_file) != strtoul(argv[3], NULL, 0) * 16){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        fclose(resulting_file);
    }
    trampolines_gen:
    {
        char* resulting_file_dir = "statichook_result";
        char path_to_resulting_file[1024];
        char resulting_file_name[1024] = {0};
        strcpy(resulting_file_name, argv[1]);
        strcpy(resulting_file_name, basename(resulting_file_name));
        snprintf(path_to_resulting_file, 1024, "%s/%s", resulting_file_dir, resulting_file_name);
        FILE* resulting_file = fopen(path_to_resulting_file, "r+b");
        if(!resulting_file){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        
        lc_segment_64 injseg_cmd = get_segment_by_name(resulting_file, "__INJT");
        for (int i = 0; i < strtoul(argv[3], NULL, 0); i++)
        {
            if(strcmp(hook_functions[i].hook_func_name, "CALL_ONLY") == 0){continue;}

            uint32_t offset = injseg_cmd.vmaddr - CPT[i].orig_func_off + 0x4000 + hook_functions[i].hook_fulc_local_off;
            uint32_t trpln_instrl = get_arm64_rel_jmp(offset);
            if(fseek(resulting_file, CPT[i].orig_func_off, SEEK_SET)){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
            if(fwrite((char*)&trpln_instrl, 1, 4, resulting_file) != 4){printf("%s%d\n", "error in line: ", __LINE__); goto end;}
        }
        fclose(resulting_file);
    }

    
    end:
    if (initial_file) fclose(initial_file); 
    if (injected_file) fclose(injected_file);
    printf("\n\nGLOBAL DONE\n\n");
    return 0;
}
