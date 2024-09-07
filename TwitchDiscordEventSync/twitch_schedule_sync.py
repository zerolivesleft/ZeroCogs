from redbot.core import commands, Config
import discord
from discord.ext import tasks
import aiohttp
import os
from datetime import datetime, timedelta, timezone
import logging

class TwitchScheduleSync(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.logger = logging.getLogger("red.TwitchScheduleSync")
        self.config = Config.get_conf(self, identifier=5599887514)  # Use a unique identifier
        default_global = {
            "twitch_client_id": None,
            "twitch_client_secret": None,
            "twitch_username": None
        }
        self.config.register_global(**default_global)
        self.twitch_client_id = None
        self.twitch_client_secret = None
        self.twitch_username = None
        bot.loop.create_task(self.initialize())
        self.sync_schedule.start()

    async def initialize(self):
        self.twitch_client_id = await self.config.twitch_client_id()
        self.twitch_client_secret = await self.config.twitch_client_secret()
        self.twitch_username = await self.config.twitch_username()

    def cog_unload(self):
        self.sync_schedule.cancel()

    @tasks.loop(hours=24)
    async def sync_schedule(self):
        await self._do_sync()

    async def _do_sync(self):
        # Fetch Twitch access token
        access_token = await self.get_twitch_access_token()
        if not access_token:
            raise Exception("Failed to get Twitch access token")

        # Fetch Twitch schedule
        schedule = await self.fetch_twitch_schedule(access_token)
        if not schedule:
            raise Exception("Failed to fetch Twitch schedule")

        # Sync with Discord events
        await self.sync_discord_events(schedule)

    async def get_twitch_access_token(self):
        url = "https://id.twitch.tv/oauth2/token"
        params = {
            "client_id": self.twitch_client_id,
            "client_secret": self.twitch_client_secret,
            "grant_type": "client_credentials"
        }
        
        # Filter out None values from params
        params = {k: v for k, v in params.items() if v is not None}

        async with aiohttp.ClientSession() as session:
            async with session.post(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data["access_token"]
        return None

    async def fetch_twitch_schedule(self, access_token):
        user_id = await self.get_twitch_user_id(access_token)
        if not user_id:
            return None
        url = f"https://api.twitch.tv/helix/schedule?broadcaster_id={user_id}"
        headers = {
            "Client-ID": self.twitch_client_id,
            "Authorization": f"Bearer {access_token}"
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data
        return None

    async def get_twitch_user_id(self, access_token):
        url = f"https://api.twitch.tv/helix/users?login={self.twitch_username}"
        headers = {
            "Client-ID": self.twitch_client_id,
            "Authorization": f"Bearer {access_token}"
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data["data"]:
                        return data["data"][0]["id"]
        return None

    async def sync_discord_events(self, schedule):
        guild = self.bot.guilds[0]  # Assuming the bot is in only one guild
        if "data" not in schedule or "segments" not in schedule["data"]:
            self.logger.info("No segments found in the schedule")
            return
        for segment in schedule["data"]["segments"]:
            self.logger.info(f"Processing segment: {segment}")
            start_time = datetime.fromisoformat(segment["start_time"].rstrip('Z')).replace(tzinfo=timezone.utc)
            
            # Check if end_time is provided, otherwise default to 4 hours
            if "end_time" in segment and segment["end_time"]:
                end_time = datetime.fromisoformat(segment["end_time"].rstrip('Z')).replace(tzinfo=timezone.utc)
            else:
                end_time = start_time + timedelta(hours=4)
            
            event_name = f"Twitch Stream: {segment['title']}"

            # Check if event already exists
            existing_event = discord.utils.get(await guild.fetch_scheduled_events(), name=event_name)
            if existing_event:
                await existing_event.edit(
                    name=event_name,
                    description=segment["category"]["name"],
                    start_time=start_time,
                    end_time=end_time
                )
            else:
                await guild.create_scheduled_event(
                    name=event_name,
                    description=segment["category"]["name"],
                    start_time=start_time,
                    end_time=end_time,
                    privacy_level=discord.PrivacyLevel.guild_only,
                    entity_type=discord.EntityType.external,
                    location=f"https://twitch.tv/{self.twitch_username}"
                )

            # Image selection
            image_url = self.get_event_image_url(segment)
            image = await self.fetch_image(image_url) if image_url else None

    def get_event_image_url(self, segment):
        # Default to category box art
        image_url = segment.get("category", {}).get("box_art_url", "")

        if image_url:
            # Replace width and height placeholders with desired dimensions
            image_url = image_url.replace("{width}x{height}", "285x380")
        else:
            # Fallback image if no category image is available
            image_url = "https://path.to/your/fallback/image.png"

        # You can add more custom logic here, e.g., based on game name or stream title
        game_name = segment.get("category", {}).get("name", "").lower()
        if "minecraft" in game_name:
            image_url = "https://path.to/your/minecraft/image.png"
        elif "fortnite" in game_name:
            image_url = "https://path.to/your/fortnite/image.png"

        return image_url

    @sync_schedule.before_loop
    async def before_sync_schedule(self):
        await self.bot.wait_until_ready()

    @commands.command()
    async def force_sync(self, ctx):
        """Force a sync of the Twitch schedule to Discord events"""
        await self.sync_schedule()
        await ctx.send("Twitch schedule sync completed.")

    @commands.command()
    @commands.is_owner()
    async def show_twitch_settings(self, ctx):
        """Display current Twitch API settings."""
        client_id = await self.config.twitch_client_id()
        client_secret = await self.config.twitch_client_secret()
        username = await self.config.twitch_username()

        masked_secret = "****" + client_secret[-4:] if client_secret else None

        settings = (
            f"Twitch Client ID: {client_id or 'Not set'}\n"
            f"Twitch Client Secret: {masked_secret or 'Not set'}\n"
            f"Twitch Username: {username or 'Not set'}"
        )
        await ctx.send(f"```\n{settings}\n```")

    @commands.group()
    @commands.is_owner()
    async def twitchset(self, ctx):
        """Configure Twitch API settings."""
        pass

    @twitchset.command()
    async def clientid(self, ctx, *, client_id: str):
        """Set the Twitch Client ID."""
        await self.config.twitch_client_id.set(client_id)
        await ctx.send("Twitch Client ID set.")
        await self.initialize()

    @twitchset.command()
    async def clientsecret(self, ctx, *, client_secret: str):
        """Set the Twitch Client Secret."""
        await self.config.twitch_client_secret.set(client_secret)
        await ctx.send("Twitch Client Secret set.")
        await self.initialize()

    @twitchset.command()
    async def username(self, ctx, *, username: str):
        """Set the Twitch Username."""
        await self.config.twitch_username.set(username)
        await ctx.send("Twitch Username set.")
        await self.initialize()

async def setup(bot):
    cog = TwitchScheduleSync(bot)
    await cog.initialize()
    await bot.add_cog(cog)