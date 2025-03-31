# Monitor de Rede com Telegram e Relatórios PDF

Este projeto é um monitor de rede que utiliza o Nmap para escanear dispositivos conectados, armazena informações numa base de dados SQLite, envia notificações via Telegram e gera relatórios em PDF. Inclui também uma interface web para visualização e gestão dos dados.

## Funcionalidades

-   **Escaneamento de Rede:** Utiliza o Nmap para descobrir dispositivos conectados na rede.
-   **Armazenamento de Dados:** Armazena informações dos dispositivos (IP, MAC, última vez visto) e logs de atividades numa base de dados SQLite.
-   **Notificações Telegram:** Envia alertas via Telegram quando novos dispositivos são detetados.
-   **Interface Web:** Interface web para visualizar dispositivos conectados, logs e histórico de conexões.
-   **Relatórios PDF:** Geração de relatórios em PDF para dispositivos, logs e histórico.
-   **Autenticação:** Proteção de acesso com login e logout.
-   **Histórico de Conexões:** Gráfico do histórico de conexões.
-   **Pesquisa e Paginação:** Pesquisa e paginação de logs.

## Pré-requisitos

-   Python 3.x
-   Nmap instalado no sistema operativo.
-   Conta no Telegram e criação de um bot.

## Instalação

1.  Clona o repositório:

    ```bash
    git clone <URL_DO_REPOSITORIO>
    cd <NOME_DO_REPOSITORIO>
    ```

2.  Cria um ambiente virtual (recomendado):

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # No Linux/macOS
    venv\Scripts\activate  # No Windows
    ```

3.  Instala as dependências:

    ```bash
    pip install Flask requests python-dotenv reportlab nmap-python
    ```

4.  Cria um ficheiro `.env` na raiz do projeto com as seguintes variáveis de ambiente:

    ```
    APP_USERNAME=o_teu_utilizador
    APP_PASSWORD=a_tua_senha
    TELEGRAM_BOT_TOKEN=o_teu_token_do_bot_telegram
    TELEGRAM_CHAT_ID=o_teu_chat_id_telegram
    ```

    -   `APP_USERNAME` e `APP_PASSWORD`: Credenciais para aceder à interface web.
    -   `TELEGRAM_BOT_TOKEN`: Token do teu bot do Telegram.
    -   `TELEGRAM_CHAT_ID`: ID do chat onde as notificações serão enviadas.

5.  Executa a aplicação:

    ```bash
    python app.py
    ```

    A aplicação estará disponível em `http://0.0.0.0:5654/`.

## Configuração

-   A variável `network` no código define a rede a ser escaneada. Ajusta-a conforme necessário.
-   As configurações do Telegram são definidas no ficheiro `.env`.
-   A base de dados SQLite (`network_devices.db`) é criada automaticamente na primeira execução.

## Utilização

1.  Acede à interface web com as credenciais definidas no ficheiro `.env`.
2.  Visualiza os dispositivos conectados, logs e histórico de conexões.
3.  Gera relatórios em PDF.
4.  Recebe notificações via Telegram sobre novos dispositivos detetados.

## Dependências

-   Flask: Framework web para a interface.
-   requests: Para enviar mensagens via Telegram.
-   python-dotenv: Para carregar variáveis de ambiente do ficheiro `.env`.
-   reportlab: Para geração de relatórios em PDF.
-   sqlite3: Para a base de dados.
-   nmap: Para o escaneamento de rede.

## Notas

-   Certifica-te de que o Nmap está instalado e configurado corretamente no teu sistema.
-   A segurança das credenciais no ficheiro `.env` é crucial. Evita partilhar este ficheiro.
-   A precisão do escaneamento de rede depende da configuração da rede e do Nmap.
-   Para testes locais, altera `debug=False` para `debug=True` na linha `app.run()` para ativar o modo de depuração.
-   Para testar em rede local, altera o host para o ip da maquina, exemplo: `app.run(host="192.168.1.193", port=5654, debug=False)`
