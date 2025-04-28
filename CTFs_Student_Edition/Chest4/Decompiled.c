
int __cdecl main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  size_t sVar2;
  undefined8 uVar3;
  undefined8 local_48;
  undefined2 local_40;
  undefined6 uStack_3e;
  undefined2 uStack_38;
  undefined8 local_36;
  undefined8 local_28;
  undefined2 local_20;
  undefined6 uStack_1e;
  undefined2 uStack_18;
  undefined8 local_16;
  
  __main();
  if (_Argc == 2) {
    local_28 = 0x7b67737c51525045;
    local_20 = 0x7569;
    uStack_1e = 0x68716a626675;
    uStack_18 = 0x756f;
    local_16 = 0x7e686d68766768;
    local_48 = 0x502010103020302;
    local_40 = 0x304;
    uStack_3e = 0x10305030102;
    uStack_38 = 0x706;
    local_36 = 0x101ffff040203;
    sVar2 = strlen(_Argv[1]);
    if ((sVar2 == 0x19) &&
       (uVar3 = check_pw((longlong)_Argv[1],(longlong)&local_28,(longlong)&local_48),
       (int)uVar3 != 0)) {
      printf("Yes, %s is correct!\n",_Argv[1]);
      return 0;
    }
    printf("No, %s is not correct.\n",_Argv[1]);
    iVar1 = 1;
  }
  else {
    printf("Need exactly one argument.\n");
    iVar1 = -1;
  }
  return iVar1;
}




undefined8 check_pw(longlong param_1,longlong param_2,longlong param_3)

{
  int local_c;
  
  local_c = 0;
  do {
    if ((char)(*(char *)(param_2 + local_c) - *(char *)(param_3 + local_c)) !=
        *(char *)(param_1 + local_c)) {
      return 0;
    }
    local_c = local_c + 1;
  } while ((*(char *)(param_2 + local_c) != '\0') && (*(char *)(param_1 + local_c) != '\0'));
  return 1;
}