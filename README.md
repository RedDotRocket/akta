<div align="center">
    <picture>
        <source srcset="./static/akta-logo-dark.png" media="(prefers-color-scheme: dark)">
        <source srcset="./static/akta-logo-light.png" media="(prefers-color-scheme: light)">
        <img src="./static/akta-logo-dark.png" alt="Akta logo" width="400px">
    </picture>
</div>

Akta is a prototype project designed to enable secure and verifiable interactions between AI agents. It establishes a framework for time-bound capability-based access control, allowing agents to delegate tasks and share resources with fine-grained control. The system leverages concepts from Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) to create a cryptographically and auditable environment for autonomous agent operations.

In essence, Akta tries to answer what does a fully autonomous Agent to Agent authorization grant look like with no hoomans around? a.k.a an Agent delegating to another Agent. The human element is derived from owning the entire trust chain, from the root issuer to the agents specific delegated
skills (to use the A2A termonology).

**Important Note:** *Akta is currently a prototype. The codebase has not undergone a third-party security audit and is not yet considered suitable or secure for production environments. I am not sure what I am doing with the project at the moment, but if your curious in building this out to more, ping me!.*

## A2A Agent Framework

Akta is designed to be used with the A2A Agent Framework. It ingests agent cards
and uses them to discover skills and capabilities of agents and perform the
cryptographic policy assignment and delegation of those skills.

## Quick Start

To quickly see Akta in action, you can run the demo script or there is a full
CLI you can use to create keys, issue credentials, and delegate skills etc

```bash
akta --help
Usage: akta [OPTIONS] COMMAND [ARGS]...

  Akta - Authenticated Knowledge & Trust Architecture for AI Agents

Options:
  --help  Show this message and exit.

Commands:
  claim     Create and manage Verifiable Credentials using Linked Data...
  keys      Create and manage keys for DID Documents and Verifiable...
  registry  Manage Verifiable Credentials in a Verifiable Data Registry
  token     Generate or verify Bearer Tokens from signed VC
```

### Installation

Clone the repository:

```bash
git clone https://github.com/RedDotRocket/akta.git
cd akta
```

```bash
pip install .
```

### Running the Demo

First run the vdr service:

```bash
akta vdr serve
```

Then run the demo script:

```bash
./test_delegation_workflow.sh
```

## Demo Walkthrough

### What Just Happened?

The scenario is that there are three actors: an Issuer (IA), AgentBob (AB), and AgentCharlie (AC). 

Each actor has a Decentralized Identifier (DID). The demo uses `did:key` for simplicity, but Akta supports various DID methods. I did think of creating a `did:agent`, would be a fun idea, but I didn't have time to implement it.

The skills are based on a mocked Google Maps API, where Agent Bob is granted the ability to generate maps, alongside a capability to delegate that map generation to Agent Charlie. I originally planned of having a scenario where two humans wanted to meet, but prefered to keep their current locations private, so Alice delegrates the map generation to her Agent, Bob, who can then generate a map of the region they ask for and pass it to Agent Charlie, who can then use it to compute a rendezvous point for her Human Jane. This where the w3c ["Verifiable Presentation"]([https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations]) could be interesting , but I didn't have time to implement that yet! The same holds for [Zero Knowledge Proofs](https://www.w3.org/TR/vc-data-model-2.0/#zero-knowledge-proofs)

Side note: I freaking love all this DID stuff, its super cool. It's a shame its not too
popular, [opinion ->] and it likely won't be while everything resolves around catering
to big tech and whatever works best for their business models. By the way, I am
new to the spec, so w3c eggheads, please don't eat my head off if I get something
wrong, I am still digging into it and learning as I go.

So...

It all starts with the Issuer, who grabs hold of Agent Bob's AgentCard (running on http://localhost/.well-known/agent.json),
that contains metadata about Agent Bob's capabilities and skills (for the demo we use a map generation skill).

```python
curl -s http://127.0.0.1:8050/api/v1/.well-known/agent.json |jq

{
  "capabilities": {
    "pushNotifications": false,
    "stateTransitionHistory": false,
    "streaming": false
  },
  "defaultInputModes": [
    "text"
  ],
  "defaultOutputModes": [
    "text"
  ],
  "description": "This agent will give you a map of the region you ask for",
  "documentationUrl": "http://localhost:8050/docs",
  "name": "Map Agent",
  "provider": {
    "organization": "Google, Inc.",
    "url": "https://google.com"
  },
  "securitySchemes": {
    "bearerAuth": {
      "scheme": "bearer",
      "type": "http"
    }
  },
  "skills": [
    {
      "description": "Generate a map of the region you ask for",
      "examples": [
        "generate a map of the declared region"
      ],
      "id": "google-maps",
      "inputModes": [
        "text"
      ],
      "name": "Generate a map of the region you ask for",
      "outputModes": [
        "text"
      ],
      "tags": [
        "map:generate"
      ]
    }
  ],
  "supportsAuthenticatedExtendedCard": false,
  "url": "http://localhost:8050",
  "version": "1.0.0"
}
```

It then issues a Verifiable Credential (VC) to Bob, granting him the ability to both use, and delegate his skills (` "canDelegate": true`). This VC is signed by the Issuer and stored in a Verifiable Credential Store (the vdr service you started). `canDelegate` is of course vastly overscopped and over-simplified, i expect in a real world scenario this would reference a policy that defines a list of who can be delegated to etc, and what skills can be delegated, for how long and how many times etc.

There is also a usage limit of 10, meaning Bob can generate maps up to 10 times before the credential expires.

```json
--- Credential Subject ---
{
  "id": "did:key:z6MkkZPDFLLri7cDFDdwPNrQhuFHfyNNw9HhBuV3UbW6zAbR",
  "skills": [
    {
      "id": "google-maps",
      "granted": true,
      "scope": [
        "map:generate"
      ],
      "usageLimit": 10,
      "canDelegate": true
    }
  ]
}
```

We also capture evidence of the AgentCard state at the time of issuance, which is useful for auditing and verification purposes. This is based on the w3c spec
which definees an evidence object [https://www.w3.org/TR/vc-data-model-2.0/#evidence].

```json
--- Evidence ---
[
  {
    "id": "http://localhost:8050/api/v1/.well-known/agent.json",
    "type": "AgentCardSnapshot",
    "description": "AgentCard used for this issuance",
    "hash": "QmNcEGxoQZcKzjKcjKPj1ZkPZnT4wSsmBfxuMAq4DUHH2F"
  }
]
```

It is also possible to grab more evidence, with `--tls-fingerprint` and more.

My idea is these would be stuffed in some sort of merkle tree, so you can prove the state of the AgentCard at the time of issuance. As said, this is a prototype, so I haven't implemented that yet
and these are not peer reviewed security protocols.

Bob now has a full Verifiable Credential that proves he has the skills to generate maps and can delegate those skills to others. w00t!

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:77629d25-8eab-4eab-a048-9faacd6f6246",
  "type": [
    "VerifiableCredential",
    "AgentSkillAccess"
  ],
  "issuer": "did:key:z6MkuijvTUcK1VEQDDK66ysxcenkBuvw7Jc56P7wSdCopvR7",
  "issuanceDate": "2025-07-02T07:47:30.280957Z",
  "credentialSubject": {
    "id": "did:key:z6MkkZPDFLLri7cDFDdwPNrQhuFHfyNNw9HhBuV3UbW6zAbR",
    "skills": [
      {
        "id": "google-maps",
        "granted": true,
        "scope": [
          "map:generate"
        ],
        "usageLimit": 10,
        "canDelegate": true
      }
    ]
  },
  "evidence": [
    {
      "id": "http://localhost:8050/api/v1/.well-known/agent.json",
      "type": "AgentCardSnapshot",
      "description": "AgentCard used for this issuance",
      "hash": "QmNcEGxoQZcKzjKcjKPj1ZkPZnT4wSsmBfxuMAq4DUHH2F"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-07-02T07:47:30.478022Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:z6MkuijvTUcK1VEQDDK66ysxcenkBuvw7Jc56P7wSdCopvR7#z6MkuijvTUcK1VEQDDK66ysxcenkBuvw7Jc56P7wSdCopvR7",
    "proofValue": "5SF3ziGdsGB8h5P9rfj1RL6VBuGFKGMQC7R9G4UTMhj1A2JcsKc7j6i6xwLB8oZxrAFvDLLfiR67bGchnrcV3BD"
  }
}
```

Next Bob (AgentBob) uses his VC to delegate his skills to Agent Charlie. Bob mints a new Verifiable Credential that chains to his original VC, and delegates Charlie the use
of map generation skills. This delegated VC is also signed by Bob and stored in the VC Store. 

We now have a trust chain of Issuer -> Bob -> Charlie, where Charlie can use the skills granted by Bob, Issuer can revoke Bob's VC, and Bob can revoke Charlie's delegated VC.

Issuer gave Bob generate map skills, Bob delegated those skills to Charlie, and now Charlie can use those skills.

Cheers Bob! You're done for now mate, go grab a cuppa!

Charlie now uses Delegated VC

A Bearer token is created from Charlie’s signed delegated VC. The token is used to call the `/map/generate` API (mocked google maps).

The response is validated — if successful (HTTP 200), delegation worked.

Delegation Denied Scenario

A second VC is issued to Bob with canDelegate: false.

Bob attempts to delegate to Charlie using this new VC.

A delegated VC is created and signed anyway.

Charlie tries to use it, but API returns HTTP 403, proving delegation enforcement works.

## Contributing

I love getting contributions, from engineers of all levels and background!

Don't be put off contributing, we're all learning as we go and everyone starts
somewhere.

You could always look for good first issues to get started, and tag me in the PR
(@lukehinds) and I am happy to give you plently of friendly support and guidance (if you want it).

## Using Akta?

If you're experimenting with Akta, please let us know! We'd love to hear about
your use case and how it's working for you!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.