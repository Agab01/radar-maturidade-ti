
#  RADAR.TI - Sistema de Avaliação de Maturidade

O **RADAR.TI** é uma solução robusta desenvolvida para diagnosticar e mensurar o grau de maturidade da infraestrutura e dos processos de Tecnologia da Informação em organizações. Através de uma interface ágil e um motor de cálculo preciso, a ferramenta transforma respostas qualitativas em **scores técnicos segmentados**, oferecendo uma visão 360° da saúde digital do negócio.

---

##  Funcionalidades Principais

* **Diagnóstico por Quesitos:** Avaliação baseada em critérios técnicos de governança e conformidade.
* **Cálculo Automático de Score:** Algoritmo que gera médias por categoria e um índice de maturidade geral.
* **Dashboards em Tempo Real:** Visualização clara do nível de prontidão tecnológica.
* **Acesso Mobile via QR Code:** Interface otimizada para aplicação de diagnósticos em campo através de dispositivos móveis.
* **Monitoramento Integrado:** Uso de Web Analytics e Speed Insights para garantir performance e rastreabilidade.

---

##  Stack Tecnológica

* **Backend:** [Python](https://www.python.org/) com o framework [Flask](https://flask.palletsprojects.com/).
* **Banco de Dados:** [PostgreSQL](https://www.postgresql.org/) (Hospedado via [Supabase](https://supabase.com/)).
* **Frontend:** HTML5 e CSS3 com estética **Brutalista** (foco em performance e clareza).
* **Deployment:** [Vercel](https://vercel.com/) (Infraestrutura Serverless).
* **CI/CD:** [GitHub Actions](https://github.com/features/actions).

---

##  Segurança e Governança

Como o projeto lida com dados sensíveis de infraestrutura corporativa, a segurança foi integrada desde o primeiro dia (Privacy by Design):

* **Proteção de Credenciais:** Uso rigoroso de variáveis de ambiente (`.env`) para isolar chaves de banco de dados e segredos da aplicação.
* **Integridade de Dados:** Criptografia (**Hashing**) de senhas administrativas para garantir que apenas usuários autorizados gerenciem os quesitos.
* **Zero Hardcoding:** Nenhuma informação sensível é exposta no código-fonte ou enviada ao repositório público.

---

##  Como rodar o projeto localmente

1.  **Clone o repositório:**
    ```bash
    git clone https://github.com/SEU_USUARIO/radar-maturidade-ti.git
    ```
2.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure as Variáveis de Ambiente:**
    Crie um arquivo `.env` na raiz com as seguintes chaves:
    * `DATABASE_URL`
    * `SECRET_KEY`
    * `ADMIN_EMAIL`
    * `ADMIN_PASSWORD`
4.  **Execute a aplicação:**
    ```bash
    python app.py
    ```

---

##  Monitoramento de Performance

O projeto utiliza as ferramentas nativas da Vercel para garantir que o sistema esteja sempre disponível e rápido:
* **Vercel Analytics:** Acompanhamento de tráfego e engajamento.
* **Speed Insights:** Métricas de carregamento e experiência do usuário (Core Web Vitals).

---

> **Nota de Projeto:** Este sistema foi desenvolvido como parte de um estudo prático de Governança de TI, unindo desenvolvimento ágil com práticas recomendadas de segurança cibernética.

---
