# 🦀 Blog API

![License](https://img.shields.io/static/v1?label=license&message=MIT&color=orange) &nbsp;
![Cargo version](https://img.shields.io/static/v1?label=cargo&message=v0.1.0&color=yellow) &nbsp;
![Repository size](https://img.shields.io/github/repo-size/bush1D3v/navarro_blog_api?color=blue) &nbsp;
![Pull request](https://img.shields.io/static/v1?label=PR&message=welcome&color=green)

## 🔍 Sobre o Projeto

A **Blog API** é uma aplicação de desenvolvimento web focada em fornecer funcionalidades para gerenciar e interagir com o conteúdo de um blog pessoal através de chamadas programáticas.

## 🛠️ Tecnologias e Ferramentas Utilizadas

<div align='center'>
   <img align='center' height='60' width='85' title='Rust' alt='rust' src='https://github.com/bush1D3v/101acessorios_api/assets/133554156/b90e29a7-31f7-4a92-978f-81b8240eb148' /> &nbsp;
   <img align='center' height='60' width='60' title='Actix' alt='actix' src='https://github.com/bush1D3v/101acessorios_api/assets/133554156/3b9ec599-9db6-48b2-afed-9f336f4f7bef' /> &nbsp;
   <img align='center' height='65' width='65' title='Nginx' alt='nginx' src='https://github.com/bush1D3v/101acessorios_api/assets/133554156/7a445df4-b341-4ab0-97d5-0084638dec99' /> &nbsp;
   <img align='center' height='60' width='60' title='Redis' alt='redis' src='https://github.com/devicons/devicon/blob/master/icons/redis/redis-original.svg' /> &nbsp;
   <img align='center' height='60' width='60' title='Makefile' alt='makefile' src='https://github.com/bush1D3v/bush1D3v/assets/133554156/7d964e81-c0a3-476f-a26b-8813550557aa' />
   <img align='center' height='55' width='70' title='PostgreSQL' alt='postgresql' src='https://github.com/devicons/devicon/blob/master/icons/postgresql/postgresql-original.svg' />
   <img align='center' height='48' width='48' title='Insomnia' alt='insomnia' src='https://github.com/bush1D3v/my_portfolio/assets/133554156/75a3fffd-792e-4250-8ef5-2abb615e38a0' /> &nbsp;
   <img align='center' height='53' width='49' title='Beekeeper' alt='beekeeper' src='https://github.com/bush1D3v/my_portfolio/assets/133554156/0d5b4b55-546c-4bc0-a25c-dfc9116fe993' />
   <img align='center' height='60' width='70' title='Swagger' alt='swagger' src='https://github.com/bush1D3v/tsbank_api/assets/133554156/6739401f-d03b-47f8-b01f-88da2a9075d1' />
   <img align='center' height='70' width='70' title='Docker' alt='docker' src='https://github.com/devicons/devicon/blob/master/icons/docker/docker-plain.svg' />
</div>

## 🏗 Estrutura e Arquitetura

O projeto segue os princípios da **arquitetura limpa**, e o código foi organizado de acordo com os princípios de **modularidade**, **reutilização** e **responsabilidade única**.

## 🐳 Docker

Com a adição do Docker, você agora pode utilizar dos scripts fornecidos em `package.json` para poder construir a imagem docker e rodar o container da aplicação.

Para isso, segue a lista de funções de cada script:

> `docker-build`: Constrói a imagem docker do projeto <br> `docker-start`: Sobe e roda/só roda o container navarro_blog_api <br> `docker-stop`: Para o container navarro_blog_api

# 🖋️ Contribuindo para o Blog

Agradeço pelo seu interesse em contribuir para o meu **Blog**. Sua ajuda é **valiosa** para melhorar e **expandir** minha aplicação. Abaixo estão as **diretrizes** e os **passos** para contribuir com meu projeto.

## 💻 Como Contribuir

### 🌳 Forkando o Repositório

Antes de começar, você **deverá** forkar o repositório do projeto para **seu perfil**.

### 🖨 Clonando seu Repositório

Após o Fork, você **precisará** clonar o repositório forkado para seu **ambiente de desenvolvimento local**:

```
git clone https://github.com/{seu-usuario}/navarro_blog_api.git
cd navarro_blog_api
```

### ⏬ Instalando Dependências

Certifique-se de ter Node.js instalado no seu sistema. Em seguida, instale as dependências necessárias:

```
npm install
```

ou

```
yarn install
```

ou

```
pnpm install
```

### 🆕 Criando uma Branch

Antes de iniciar qualquer trabalho, crie uma branch separada para a sua contribuição. Use um nome descritivo para a sua branch:

```
git checkout -b feature/nova-funcionalidade
```

### 🔨 Fazendo Alterações

Faça as alterações necessárias no código, adicione novos recursos ou correções de bugs.

### 🧪 Testando

Garanta que suas alterações não quebraram nenhum recurso existente. Execute os testes e certifique-se de que todos passam:

```
npm run test
```

ou

```
yarn test
```

ou

```
pnpm test
```

### 📝 Documentando

Mantenha a documentação atualizada. Se você adicionou novos recursos, verifique se eles estão devidamente documentados no README.

### 📊 Compromissos e Push

Após concluir suas alterações e testá-las, faça um commit das alterações:

```
git add .
git commit -m <tipo de alteração>(nomeDoArquivo): Nova funcionalidade
```

Em seguida, envie suas alterações para o repositório:

```
git push origin feature/nova-funcionalidade
```

### 📨 Solicitando um Pull Request (PR)

Vá para o repositório no GitHub e crie um Pull Request para que sua contribuição seja revisada. Certifique-se de descrever suas alterações e fornecer informações contextuais.

### 👁 Revisão e Fusão

Após criar um Pull Request, nossa equipe revisará suas alterações e fornecerá feedback. Uma vez aprovado, suas alterações serão mescladas no projeto principal.

## 💼 Diretrizes Gerais

- Mantenha o código limpo e legível.
- Siga as boas práticas de desenvolvimento.
- Respeite as convenções de nomenclatura existentes.
- Documente adequadamente as alterações, recursos ou correções.

#

**_Agradeço pela sua contribuição e espero que possamos trabalhar juntos para tornar o meu Blog ainda melhor. Se você tiver alguma dúvida ou precisar de ajuda, não hesite em entrar em contato comigo. Juntos, podemos criar uma aplicação mais robusta e eficiente._**
