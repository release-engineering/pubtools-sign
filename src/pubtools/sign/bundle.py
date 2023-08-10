import click


from .signers.msgsigner import msg_clear_sign, msg_container_sign


@click.group()
def cli():
    """Pubtools-sign multi command bundle."""
    pass


cli.add_command(msg_clear_sign, name="msg-clear-sign")
cli.add_command(msg_container_sign, name="msg-container-sign")
