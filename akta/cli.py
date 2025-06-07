import click

from akta.commands.claim import claim
from akta.commands.keys import keys
from akta.commands.registry import registry
from akta.commands.token import token
from akta.commands.vdr import vdr


@click.group()
def cli():
    """Acta - Authenticated Knowledge & Trust Architecture for AI Agents"""
    pass


cli.add_command(keys)
cli.add_command(claim)
cli.add_command(token)
cli.add_command(registry)
cli.add_command(vdr)


if __name__ == "__main__":
    cli() 