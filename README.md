# RR Mod Manager

Gerenciador de mods local para **Retro Rewind - Video Store Simulator**.

O RR Mod Manager permite importar mods, organizar perfis, ativar e desativar
mods, visualizar conflitos e aplicar mudanças com backup e restauração.

## Compatibilidade

- Retro Rewind pela Steam, build `23896268`.
- Windows 11 x64.
- Linux x64 com Steam/Proton.

Outras versões do jogo não foram validadas.

## Download e instalação

Baixe a versão mais recente na seção **Releases** deste repositório.

### Windows 11

Baixe `RR.Mod.Manager_0.1.0_x64-setup.exe` e execute o instalador. A instalação
é feita somente para o usuário atual e não exige privilégios de administrador.

O instalador ainda não possui assinatura digital. Por isso, o Windows pode
mostrar um aviso de editor desconhecido.

### Linux

Baixe `RR.Mod.Manager_0.1.0_amd64.AppImage`, permita a execução do arquivo e
abra-o normalmente.

```bash
chmod +x RR.Mod.Manager_0.1.0_amd64.AppImage
./RR.Mod.Manager_0.1.0_amd64.AppImage
```

## Limitações atuais

- Não possui atualização automática.
- Não possui login ou downloads automáticos do Nexus Mods.
- Mods com DLLs nativas desconhecidas não podem ser considerados seguros apenas
  pela inspeção do gerenciador.

Feche o jogo antes de aplicar mudanças em um perfil.

## Sobre este repositório

Este é o repositório público de distribuição do RR Mod Manager. Ele contém a
documentação pública; os instaladores ficam anexados às Releases.
