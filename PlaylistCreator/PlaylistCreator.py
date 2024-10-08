from redbot.core import commands
from redbot.core.bot import Red
import discord
from discord import app_commands

class PlaylistCreator(commands.Cog):
    def __init__(self, bot: Red):
        self.bot = bot

    @app_commands.command()
    async def playlist_test(self, interaction: discord.Interaction):
        """A test command for the PlaylistCreator cog."""
        await interaction.response.send_message("PlaylistCreator cog is working!")