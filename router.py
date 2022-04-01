
from fastapi import Depends, HTTPException
from fastapi_crudrouter import SQLAlchemyCRUDRouter
from fastapi.security import OAuth2PasswordRequestForm
from .authMKT import token_auth2

from app.db import Base, get_db
from app.security import (UserInDB, abm_users_db, fake_hash_password,
                          token_auth1)


''' SORTED IMPORTS '''

from app.tables.accounts import *
from app.tables.bayerpersona import *
from app.tables.bc_bp import *
from app.tables.bc_icp import *
from app.tables.bc_pers import *
from app.tables.bj_icp import *
from app.tables.buyersjourney import *
from app.tables.buyingcomitee import *
from app.tables.camp_cont import *
from app.tables.camp_kpi import *
from app.tables.camp_pers import *
from app.tables.camp_stgs import *
from app.tables.campaign_goals import *
from app.tables.campaign import *
from app.tables.cg_camp import *
from app.tables.companies import *
from app.tables.cont_type import *
from app.tables.content import *
from app.tables.distr_channels import *
from app.tables.icp_ind import *
from app.tables.icp_tier import *
from app.tables.icp import * 
from app.tables.industries import *
from app.tables.jobtitle import *
from app.tables.kpi import *
from app.tables.personas import *
from app.tables.rolebp import *
from app.tables.servprod import *
from app.tables.servprodcomp import *
from app.tables.stages import *
from app.tables.tiers import *


''' Routers MODELO

router = SQLAlchemyCRUDRouter(
    schema=,
    create_schema=,
    db_model=,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix=''
)  

'''

'''         CRUD '''

routerAccounts = SQLAlchemyCRUDRouter(
    schema=accounts,
    create_schema=accountsCreate,
    db_model=accountsModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='accounts'
)


routerBayer = SQLAlchemyCRUDRouter(
    schema=Bayerpersona,
    create_schema=BayerpersonaCreate,
    db_model=BayerpersonaModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='bayerpersona'
)

routerBc_bp = SQLAlchemyCRUDRouter(
    schema=bc_bp,
    create_schema=bc_bpCreate,
    db_model=bc_bpModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='bc_bp'
)

routerBc_icp = SQLAlchemyCRUDRouter(
    schema=Bc_icp,
    create_schema=Bc_icpCreate,
    db_model=Bc_icp_Model,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='bc_icp'
)

routerbc_pers = SQLAlchemyCRUDRouter(
    schema=bc_pers,
    create_schema=bc_persCreate,
    db_model=bc_persModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='bc_pers'
)

routerbj_icp = SQLAlchemyCRUDRouter(
    schema=bj_icp,
    create_schema=bj_icpCreate,
    db_model=bj_icpModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='bj_icp'
)

routerbuyersjourney = SQLAlchemyCRUDRouter(
    schema=buyersjourney,
    create_schema=buyersjourneyCreate,
    db_model=buyersjourneyModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='buyersjourney'
)


routerBuyingcomitee = SQLAlchemyCRUDRouter(
    schema=buyingcomitee,
    create_schema=buyingcomiteeCreate,
    db_model=buyingcomiteeModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='buyingcomitee'
)

routerCamp_cont = SQLAlchemyCRUDRouter(
    schema = Camp_cont,
    create_schema = Camp_contCreate,
    db_model = Camp_cont_Model,
    dependencies=[Depends(token_auth2)],
    db = get_db,
    prefix = "camp_cont"
)

routerCamp_KPI = SQLAlchemyCRUDRouter(
    schema=Camp_KPI,
    create_schema=Camp_KPICreate,
    db_model=Camp_KPIModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='camp_kpi'
)

routerCamp_pers = SQLAlchemyCRUDRouter(
    schema=camp_pers,
    create_schema=camp_persCreate,
    db_model=camp_persModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='camp_pers'
)

"""
routerCamp_stgs = SQLAlchemyCRUDRouter(
    schema=Camp_stgs,
    create_schema=Camp_stgsCreate,
    db_model=Camp_stgs_Model,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='camp_stgs'
)

routerCampaign_goals = SQLAlchemyCRUDRouter(
    schema = Campaign_goals,
    create_schema = Campaign_goalsCreate,
    db_model = Campaign_goals_Model,
    dependencies=[Depends(token_auth2)],
    db = get_db,
    prefix = "campaing_goals"
)

routerCampaign = SQLAlchemyCRUDRouter(
    schema=Campaign,
    create_schema=CampaignCreate,
    db_model=CampaignModel,
    dependencies=[Depends(token_auth2)],
    db=get_db,
    prefix='campaigns'
)


routerCg_camp = SQLAlchemyCRUDRouter(
    schema = Cg_camp,
    create_schema = Cg_campCreate,
    db_model = Cg_camp_Model,
    dependencies=[Depends(token_auth2)],
    db = get_db,
    prefix = "cg_camp"
)


routercompanies = SQLAlchemyCRUDRouter(
    schema = Companies,
    create_schema = CompaniesCreate,
    db_model = CompaniesModel,
    dependencies=[Depends(token_auth1)],
    db = get_db,
    prefix = "Companies"
)

routerCont_type = SQLAlchemyCRUDRouter(
    schema=cont_type,
    create_schema=cont_typeCreate,
    db_model=cont_typeModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='cont_type'
)

routerContent = SQLAlchemyCRUDRouter(
    schema=content,
    create_schema=contentCreate,
    db_model=contentModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='content'
)

routerdistr_channels = SQLAlchemyCRUDRouter(
    schema=distr_channels,
    create_schema=distr_channelsCreate,
    db_model=distr_channelsModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='distr_channels'
)

routerIcp_ind = SQLAlchemyCRUDRouter(
    schema = Icp_ind,
    create_schema = Icp_indCreate,
    db_model = Icp_ind_Model,
    dependencies=[Depends(token_auth1)],
    db = get_db,
    prefix = "Icp_ind"
)


routerIcp = SQLAlchemyCRUDRouter(
    schema = Icp,
    create_schema = IcpCreate,
    db_model = Icp_Model,
    dependencies=[Depends(token_auth1)],
    db = get_db,
    prefix = "Icp"
)

routerIndustries = SQLAlchemyCRUDRouter(
    schema=Industries,
    create_schema=IndustriesCreate,
    db_model=IndustriesModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='industries'
)

routerIcp_tier = SQLAlchemyCRUDRouter(
    schema=icp_tier,
    create_schema=icp_tierCreate,
    db_model=icp_tierModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='icp_tier'
) 

routerJobtitle = SQLAlchemyCRUDRouter(
    schema=jobtitle,
    create_schema=jobtitleCreate,
    db_model=jobtitleModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='jobtitle'
)

routerKPI = SQLAlchemyCRUDRouter(
    schema=KPI,
    create_schema=KPICreate,
    db_model=KPIModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='kpi'
)

routerPersonas = SQLAlchemyCRUDRouter(
    schema=personas,
    create_schema=personasCreate,
    db_model=personasModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='personas'
)

routerRole_bp = SQLAlchemyCRUDRouter(
    schema=Role_bp,
    create_schema=RolebpCreate,
    db_model=Role_bpModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='Role_bp'
)


routerServprod = SQLAlchemyCRUDRouter(
    schema=Servprod,
    create_schema=ServprodCreate,
    db_model=ServprodModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='servprod'
)

routerServprodcomp = SQLAlchemyCRUDRouter(
    schema=Servprodcomp,
    create_schema=Servprodcomp_Create,
    db_model=ServprodcompModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='servprodcomp'
)

routerStages = SQLAlchemyCRUDRouter(
    schema=stages,
    create_schema=stagesCreate,
    db_model=stagesModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='stages'
)

routertiers = SQLAlchemyCRUDRouter(
    schema=tiers,
    create_schema=tiersCreate,
    db_model=tiersModel,
    dependencies=[Depends(token_auth1)],
    db=get_db,
    prefix='tiers'
) 
"""