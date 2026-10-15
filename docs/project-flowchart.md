# Project Flow Chart

```mermaid
flowchart TD
    subgraph Startup[FastAPI startup]
        Start([Start backend]) --> InitDB[Initialize database]
        InitDB --> StartLoop[Start background ingestion loop]
    end

    subgraph Sources[Alert sources]
        Mode{Ingestion mode}
        Wazuh[Wazuh API] --> PollWazuh[Poll and normalize alerts]
        System[System logs] --> Detect[Poll logs and detect events]
        Mock[Mock generator] --> BuildMock[Build sample alert]
        Mode --> Wazuh
        Mode --> System
        Mode --> Mock
        PollWazuh --> Common[Common alert data]
        Detect --> Common
        BuildMock --> Common
    end

    StartLoop --> Mode
    Common --> Duplicate{Already ingested?}
    Duplicate -- Yes --> NextPoll[Wait, then poll again]
    Duplicate -- No --> Sigma[Match Sigma detection rules]
    Sigma --> ML[Predict severity and confidence]
    ML --> Mitre[Map to MITRE ATT&CK]
    Mitre --> Index[Index alert in RAG store]
    Index --> Retrieve[Retrieve similar incident context]
    Retrieve --> Analyze[Generate summary and remediation<br/>offline templates or Ollama]
    Analyze --> Persist[Save enriched alert and agent<br/>to SQL database]
    Persist --> HighSeverity{High or critical?}
    HighSeverity -- Yes --> Notify[Send notification]
    HighSeverity -- No --> NextPoll
    Notify --> NextPoll
    NextPoll --> Mode

    subgraph AnalystUse[Analyst experience]
        Dashboard[Streamlit dashboard] <-->|HTTP| API[FastAPI REST API]
        API --> AlertRoutes[Alerts, stats, health, model info]
        AlertRoutes <--> Persisted[(SQL database)]

        Dashboard --> ChatRoute[POST /chat]
        ChatRoute --> ChatRAG[Retrieve similar incidents<br/>and optional alert context]
        ChatRAG --> ChatAnswer[Offline answer or Ollama response]
        ChatAnswer --> Dashboard

        Dashboard --> FeedbackRoute[POST /feedback or update status]
        FeedbackRoute --> FeedbackDB[(Feedback and alert status)]
        FeedbackDB --> Persisted
    end

    Persist -. available alert data .-> Persisted
```

The backend starts ingestion when FastAPI starts. Mock, system-log, and Wazuh
ingestion converge on the same enrichment pipeline; analysts then review and
update alerts through the dashboard and REST API. The LLM and Wazuh integrations
are optional, depending on configuration.