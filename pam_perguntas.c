#include <security/pam_modules.h>  // Módulo PAM principal
#include <security/pam_ext.h>    // Para pam_prompt e pam_syslog
#include <stdio.h>               // Para operacaes de I/O
#include <stdlib.h>              // Para srand, rand, free
#include <string.h>              // Para strcmp
#include <time.h>                // Para time (para seed do rand)
#include <strings.h>             // Para strcasecmp (comparacao de strings sem distincao de maiusculas/minusculas)
#include <syslog.h>              // Para LOG_AUTH, LOG_ERR, LOG_INFO, LOG_WARNING

// Defina as perguntas de seguranca e suas respostas correspondentes
// Certifique-se de que o numero de perguntas e respostas seja o mesmo.
static const char *questions[] = {
    "Qual eh seu sobrenome?",
    "Qual eh sua idade?",
    "Qual eh a sua cor favorita?"
};

static const char *answers[] = {
    "Flores",      // Resposta para a primeira pergunta
    "19", // Resposta para a segunda pergunta
    "Vermelho"       // Resposta para a terceira pergunta
};

// Calcula o numero de perguntas na array
#define NUM_QUESTIONS (sizeof(questions) / sizeof(questions[0]))

/*
 * pam_sm_authenticate:
 * Funcao principal de autenticacao do modulo PAM.
 * Esta funcao eh chamada para verificar as credenciais do usuario.
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int retval;
    const char *username = NULL;
    char *user_response = NULL;
    int selected_question_index;
    
    // Inicia o gerador de numeros aleatorios com base no tempo atual.
    // Isso garante que uma pergunta diferente seja sorteada a cada tentativa de login.
    srand(time(NULL));

    // Obtém o nome de usuario da sessao PAM.
    // Embora não seja estritamente necessario para a logica das perguntas,
    // eh util para logs e contexto.
    retval = pam_get_item(pamh, PAM_USER, (const void **)&username);
    if (retval != PAM_SUCCESS) {
        // Registra um erro se nao conseguir obter o nome de usuario.
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Falha ao obter nome de usuário: %s", pam_strerror(pamh, retval));
        return retval;
    }

    // Registra uma mensagem informativa no syslog sobre a autenticacao 2FA.
    pam_syslog(pamh, LOG_INFO, "Autenticando usuário: %s com pergunta de 2FA.", username ? username : "desconhecido");

    // Seleciona aleatoriamente um indice de pergunta.
    // O operador % NUM_QUESTIONS garante que o indice esteja dentro dos limites da array.
    selected_question_index = rand() % NUM_QUESTIONS;
    
    // Solicita a resposta do usuario para a pergunta selecionada.
    // PAM_PROMPT_ECHO_ON: A entrada do usuario será visivel (nao ocultada como uma senha).
    // &user_response: Ponteiro onde a resposta do usuario sera armazenada (pam_prompt aloca a memoria).
    // "%s": Formato da mensagem, que sera a pergunta selecionada.
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_response, "%s", questions[selected_question_index]);

    // Verifica se a chamada a pam_prompt foi bem-sucedida.
    if (retval != PAM_SUCCESS) {
        // Se houver um erro, libera qualquer memoria que pam_prompt possa ter alocado.
        if (user_response) {
            free(user_response);
        }
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Falha ao solicitar resposta 2FA: %s", pam_strerror(pamh, retval));
        return retval;
    }

    // Verifica se o usuario realmente forneceu uma resposta.
    if (!user_response) {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Usuário não forneceu uma resposta 2FA.");
        return PAM_AUTH_ERR; // Retorna erro de autenticacao.
    }

    // Compara a resposta do usuario com a resposta correta, ignorando maiusculas/minusculas.
    // strcasecmp retorna 0 se as strings forem identicas.
    if (strcasecmp(user_response, answers[selected_question_index]) == 0) {
        pam_syslog(pamh, LOG_INFO, "Pergunta 2FA respondida corretamente para o usuário: %s", username);
        retval = PAM_SUCCESS; // Autenticacao bem-sucedida.
        pam_info(pamh, "Autenticacao 2FA bem-sucedida. Bem-vindo(a)!");
    } else {
        // Registra um aviso se a resposta estiver incorreta.
        pam_syslog(pamh, LOG_WARNING, "Resposta 2FA incorreta para o usuário: %s. Esperado '%s', obtido '%s'", 
                   username, answers[selected_question_index], user_response);
        retval = PAM_AUTH_ERR; // Autenticação falhou.
    }

    // Libera a memoria alocada por pam_prompt para a resposta do usuario.
    if (user_response) {
        free(user_response);
        user_response = NULL;
    }

    return retval;
}

/*
 * pam_sm_setcred:
 * Gerenciamento de credenciais. Para este modulo simples, apenas retorna sucesso.
 * Normalmente, eh usado para estabelecer/destruir credenciais para o usuario.
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_acct_mgmt:
 * Gerenciamento de contas. Para este modulo simples, apenas retorna sucesso.
 * Usado para verificar a validade da conta do usuario (expiração, bloqueio, etc.).
 */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_open_session:
 * Abertura de sessao. Para este modulo simples, apenas retorna sucesso.
 * Usado para configurar o ambiente do usuario quando uma sessao eh iniciada.
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_close_session:
 * Fechamento de sessao. Para este modulo simples, apenas retorna sucesso.
 * Usado para limpar o ambiente do usuario quando uma sessao eh encerrada.
 */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * pam_sm_chauthtok:
 * Gerenciamento de tokens de autenticacao (senhas). Para este modulo simples, apenas retorna sucesso.
 * Usado para alterar senhas ou outros tokens de autenticacao.
 */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
