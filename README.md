# runZero Custom Integrations

👋 Welcome to the runZero Custom Integration library!

runZero is a total attack surface and exposure management platform that combines [active scanning](https://help.runzero.com/docs/discovering-assets/), [passive discovery](https://help.runzero.com/docs/traffic-sampling/), and API integrations to deliver complete visibility into managed and unmanaged assets across IT, OT, IoT, cloud, mobile, and remote environments. runZero can be used as a hosted service (SaaS) or managed on-premise. The runZero stack consists of one more Consoles, linked Explorers that run as light-weight services on network points-of-presence, and a command-line tool that can be used for offline data collection. runZero can be managed through the web interface, via API, or for self-hosted customers, on the command line.

If you are not a runZero user today, [sign up](https://www.runzero.com/try) for a trial that can be converted to our free Community Edition.

This repository includes **custom integrations** that run in the context of a runZero Explorer. These integrations are written in Starlark, a language similar to Python.

To create a custom integration within runZero, you will need a user account with `superuser` privileges.

You can find detailed documentation about Starlark-based integrations on the [runZero help portal](https://help.runzero.com/docs/custom-integration-scripts/).

# Getting Help

If you need help setting up a custom integration, you can create an [issue](https://github.com/runZeroInc/runzero-custom-integrations/issues/new) on this GitHub repo, and our team will work with you. If you have a Customer Success Engineer, you can also work with them directly. 

# Existing Integrations 

## Import to runZero 
- [Automox](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/automox/)
- [Carbon Black](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/carbon-black/)
- [Cortex XDR](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/cortex-xdr/)
- [Digital Ocean](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/digital-ocean/)
- [Drata](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/drata/)
- [JAMF](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/jamf/)
- [Kandji](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/kandji/)
- [Lima Charlie](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/lima-charlie/)
- [Tanium](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/tanium/)
## Export from runZero 
- [Sumo Logic](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/sumo-logic/)
## The boilerplate folder has examples to follow

1. Sample [README.md](./boilerplate/README.md) for contributing
2. Sample [script](./boilerplate/custom-integration-boilerplate.star) that shows how to use all of the supported libraries
3. Sample [config.json](./boilerplate/config.json) that gives context on the integration for automations to reference

## Contributing

We welcome contributions to this repository! Whether you're fixing a bug, adding a new feature, or improving documentation, your efforts make a difference. To ensure a smooth process, please follow these guidelines:

1. **Fork the Repository**: Start by forking this repository to your GitHub account.

2. **Create a Branch**: Create a feature branch for your changes. Use a descriptive name like `feature/new-integration` or `fix/bug-description`.

3. **Make Your Changes**: Implement your changes and test thoroughly. Ensure your code adheres to our coding standards and is well-documented.

4. **Commit Your Changes**: Write clear and concise commit messages that describe what you changed and why.

5. **Open a Pull Request (PR)**: 
   - Go to the original repository and open a pull request from your fork.
   - Provide a detailed description of your changes, including the problem your contribution solves and how it was tested.

6. **Code Review**: Collaborate with the maintainers during the review process. Be open to feedback and iterate on your changes if necessary.

7. **Merge**: Once approved, your PR will be merged by a maintainer.

---

## License

This repository is licensed under the [MIT License](./LICENSE). By contributing to this project, you agree that your contributions will be licensed under the same terms.
