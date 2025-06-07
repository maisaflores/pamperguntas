#include <security/pam_modules.h>  // Módulo PAM principal
#include <security/pam_ext.h>    // Para pam_prompt e pam_syslog
#include <stdio.h>               // Para operações de I/O
#include <stdlib.h>              // Para srand, rand, free
#include <string.h>              // Para strcmp
#include <time.h>                // Para time (para seed do rand)
#include <strings.h>             // Para strcasecmp (comparação de strings sem distinção de maiúsculas/minúsculas)
#include <syslog.h>              // Para LOG_AUTH, LOG_ERR, LOG_INFO, LOG_WARNING

// Defina as perguntas de segurança e suas respostas correspondentes
// Certifique-se de que o número de perguntas e respostas seja o mesmo.
static const char *questions[] = {
    "Qual é o nome da sua primeira mascote de estimação?",
    "Qual é a cidade natal da sua mãe?",
    "Qual é a sua cor favorita?"
};

static const char *answers[] = {
    "Toto",      // Resposta para a primeira pergunta
    "Sao Paulo", // Resposta para a segunda pergunta
    "Azul"       // Resposta para a terceira pergunta
};

// Calcula o número de perguntas na array
#define NUM_QUESTIONS (sizeof(questions) / sizeof(questions[0]))

/*
 * pam_sm_authenticate:
 * Função principal de autenticação do módulo PAM.
 * Esta função é chamada para verificar as credenciais do usuário.
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int retval;
    const char *username = NULL;
    char *user_response = NULL;
    int selected_question_index;
    
    // Inicia o gerador de números aleatórios com base no tempo atual.
    // Isso garante que uma pergunta diferente seja sorteada a cada tentativa de login.
    srand(time(NULL));

    // Obtém o nome de usuário da sessão PAM.
    // Embora não seja estritamente necessário para a lógica das perguntas,
    // é útil para logs e contexto.
    retval = pam_get_item(pamh, PAM_USER, (const void **)&username);
    if (retval != PAM_SUCCESS) {
        // Registra um erro se não conseguir obter o nome de usuário.
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Falha ao obter nome de usuário: %s", pam_strerror(pamh, retval));
        return retval;
    }

    // Registra uma mensagem informativa no syslog sobre a autenticação 2FA.
    pam_syslog(pamh, LOG_INFO, "Autenticando usuário: %s com pergunta de 2FA.", username ? username : "desconhecido");

    // Seleciona aleatoriamente um índice de pergunta.
    // O operador % NUM_QUESTIONS garante que o índice esteja dentro dos limites da array.
    selected_question_index = rand() % NUM_QUESTIONS;
    
    // Solicita a resposta do usuário para a pergunta selecionada.
    // PAM_PROMPT_ECHO_ON: A entrada do usuário será visível (não ocultada como uma senha).
    // &user_response: Ponteiro onde a resposta do usuário será armazenada (pam_prompt aloca a memória).
    // "%s": Formato da mensagem, que será a pergunta selecionada.
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_response, "%s", questions[selected_question_index]);

    // Verifica se a chamada a pam_prompt foi bem-sucedida.
    if (retval != PAM_SUCCESS) {
        // Se houver um erro, libera qualquer memória que pam_prompt possa ter alocado.
        if (user_response) {
            free(user_response);
        }
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Falha ao solicitar resposta 2FA: %s", pam_strerror(pamh, retval));
        return retval;
    }

    // Verifica se o usuário realmente forneceu uma resposta.
    if (!user_response) {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Usuário não forneceu uma resposta 2FA.");
        return PAM_AUTH_ERR; // Retorna erro de autenticação.
    }

    // Compara a resposta do usuário com a resposta correta, ignorando maiúsculas/minúsculas.
    // strcasecmp retorna 0 se as strings forem idênticas.
    if (strcasecmp(user_response, answers[selected_question_index]) == 0) {
        pam_syslog(pamh, LOG_INFO, "Pergunta 2FA respondida corretamente para o usuário: %s", username);
        retval = PAM_SUCCESS; // Autenticação bem-sucedida.
    } else {
        // Registra um aviso se a resposta estiver incorreta.
        pam_syslog(pamh, LOG_WARNING, "Resposta 2FA incorreta para o usuário: %s. Esperado '%s', obtido '%s'", 
                   username, answers[selected_question_index], user_response);
        retval = PAM_AUTH_ERR; // Autenticação falhou.
    }

    // Libera a memória alocada por pam_prompt para a resposta do usuário.
    if (user_response) {
        free(user_response);
        user_response = NULL;
    }

    return retval;
}

/*
 * pam_sm_setcred:
 * Gerenciamento de credenciais. Para este módulo simples, apenas retorna sucesso.
 * Normalmente, é usado para estabelecer/destruir credenciais para o usuário.
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_acct_mgmt:
 * Gerenciamento de contas. Para este módulo simples, apenas retorna sucesso.
 * Usado para verificar a validade da conta do usuário (expiração, bloqueio, etc.).
 */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_open_session:
 * Abertura de sessão. Para este módulo simples, apenas retorna sucesso.
 * Usado para configurar o ambiente do usuário quando uma sessão é iniciada.
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_close_session:
 * Fechamento de sessão. Para este módulo simples, apenas retorna sucesso.
 * Usado para limpar o ambiente do usuário quando uma sessão é encerrada.
 */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_chauthtok:
 * Gerenciamento de tokens de autenticação (senhas). Para este módulo simples, apenas retorna sucesso.
 * Usado para alterar senhas ou outros tokens de autenticação.
 */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
