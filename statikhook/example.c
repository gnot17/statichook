#include "get_commutate_pointer.c" 

#define get_LocalPlayer_GLOBAL_OFFSET 0x1B52318
#define SetMasterClient_GLOBAL_OFFSET 0x1B567E8
#define getIsMasterClient_GLOBAL_OFFSET 0x1B34008
#define get_PlayerList_GLOBAL_OFFSET 0x1b52608
#define Interceptor_GLOBAL_OFFSET 0x1177940
#define CloseConnection_GLOBAL_OFFSET 0x1B5660C

typedef struct 
{
    void* k1;
    void* k2;
    void* k3;
    int length;
    int k4;
    void* data;     
}mono_arr;

void* get_LocalPlayer()
{
    void*(*Call)() = (void*(*)())get_commutate_pointer(get_LocalPlayer_GLOBAL_OFFSET);
    return Call();
}
char SetMasterClient(void* player)
{
    char(*Call)(void*) = (char(*)(void*))get_commutate_pointer(SetMasterClient_GLOBAL_OFFSET);
    return Call(player);
}
char getIsMasterClient(void* player)
{
    char(*Call)(void*) = (char(*)(void*))get_commutate_pointer(getIsMasterClient_GLOBAL_OFFSET);
    return Call(player);
}
void* get_PlayerList()
{
    void*(*Call)() = (void*(*)())get_commutate_pointer(get_PlayerList_GLOBAL_OFFSET);
    return Call();
}
char CloseConnection(void* player)
{
    char(*Call)(void*) = (char(*)(void*))get_commutate_pointer(CloseConnection_GLOBAL_OFFSET);
    return Call(player);
}

void Interceptor(void* panelplrop)
{
    if((long long)panelplrop == 0){goto end;}

    void* local_plr = get_LocalPlayer();
    if(getIsMasterClient(local_plr) == 0)
    {
        SetMasterClient(local_plr);
        wait:;
        void* update_plr = get_LocalPlayer();
        if(getIsMasterClient(update_plr) == 0){goto wait;}
    }

    mono_arr* player_list = (mono_arr*)get_PlayerList(); 
    void* attacked_rem_plr_obj = *(void**)((long long)panelplrop + 0x88);
    char* attacked_plr_user_id = *(char**)((long long)attacked_rem_plr_obj + 0x38); 
    
    void* checked_player = (void*)0x141516;
    char* checked_plr_user_id = (void*)0x141516;
  
    for (int i = 0; i < player_list->length; i++)
    {
        checked_player = *(void**)((long long)player_list + 0x20 + i*8);
        checked_plr_user_id = *(char**)((long long)checked_player + 0x28);
        
        for (int j = 0; j < 56; j++)
        {
            if(attacked_plr_user_id[j] == checked_plr_user_id[j]){continue;}
            goto next_plr;
        }
        CloseConnection(checked_player);
        goto end;
        next_plr:;
    }
    end:;
    void(*Call)(void*) = (void(*)(void*))get_commutate_pointer(0x1177940);
    Call(panelplrop);
}