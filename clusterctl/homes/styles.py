"""Read-only projection consumer for the Homemaker-owned design authority.

No recipes, catalogs, selections or histories are written in Cluster. The provider
is an explicit receiving adapter for the single canonical Homemaker component;
its deployment/source/auth contract must be qualified before wiring it live.
"""
import re


def appearance_css(value, *, fonts_origin=None):
    """Render only the creator's bounded appearance, never supplied CSS or URLs."""
    if not isinstance(value, dict) or value.get('contract') != 'homemaker.resolved/v1':
        return ''
    a = value.get('appearance')
    if not isinstance(a, dict):
        return ''
    if (not all(isinstance(a.get(k), str) and re.fullmatch(r'#[a-fA-F0-9]{6}', a[k])
                for k in ('background', 'surface', 'text', 'accent')) or
            not all(isinstance(a.get(k), str) and len(a[k]) < 128 and
                    re.fullmatch(r'''[A-Za-z0-9 ,"'-]+''', a[k]) for k in ('bodyFont', 'headingFont')) or
            a.get('radius') not in ('0px', '12px') or a.get('gap') not in ('12px', '24px') or
            a.get('scheme') not in ('light', 'dark')):
        return ''
    fields = {'background':'background', 'surface':'surface', 'text':'text', 'accent':'accent',
              'bodyFont':'body-font', 'headingFont':'heading-font', 'radius':'radius', 'gap':'gap'}
    css = ':root{' + ''.join('--dm-'+name+':'+a[key]+';' for key,name in fields.items())
    css += 'color-scheme:'+a['scheme']+'}'
    if fonts_origin is not None and value.get('font_assets') is True:
        css = '@import url("'+fonts_origin+'/design-assets/styles/fonts.css");'+css
    return css

class StyleConsumer:
    def __init__(self, provider, authority, homes):
        self.provider, self.authority, self.homes = provider, authority, homes

    def resolved(self, home, surface, subject=None, *, personal=False):
        owner = self.homes[home]['owner_being_ref']
        current = self.authority.actor(subject.ref) if subject else None
        if subject and (not current or not current.enabled or current.revision != subject.revision):
            subject = None
        author = {'kind':'being','ref':owner}
        # This receiving home follows its own pair's choices. A visitor from
        # another pair does not automatically repaint an authored public home.
        viewer = {'kind':'human','ref':subject.ref} if subject and subject.kind=='human' and (personal or self.authority.paired_human(home)==subject.ref) else None
        return self.provider.resolve(subject.ref if subject else None, author=author,
                                     surface=surface, viewer_scope=viewer)
